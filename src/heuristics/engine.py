import yaml
import pandas as pd
import ipaddress # For CIDR checks
import re # For regex checks
import logging
from typing import List, Dict, Any, Optional, TypedDict, Union, Callable, Tuple
import argparse
import os
import sys

# Configure logging
logger = logging.getLogger(__name__)
# Set default logging handler to avoid "No handler found" warnings.
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


__all__ = ["HeuristicEngine"]


class Flow(TypedDict, total=False):
    """
    Represents a single network flow.
    Fields are optional as not all flows will have all data.
    """
    flow_id: int
    src_ip: str
    dest_ip: str
    src_port: int
    dest_port: int
    protocol: str
    protocol_number: int
    tls_handshake_successful: Optional[bool]
    tls_alert_code: Optional[int]
    tls_alert_description: Optional[str]
    server_name_indication: Optional[str]
    policy_id: Optional[str]
    policy_name: Optional[str]
    action: Optional[str]
    reason: Optional[str]
    threat_category: Optional[str]
    ssl_error_code: Optional[int]


RuleCondition = TypedDict("RuleCondition", {
    "field": str,
    "operator": str,
    "value": Any
})

Rule = TypedDict("Rule", {
    "name": str,
    "output_value": Optional[str],
    "output_value_format": Optional[str],
    "conditions": Optional[List[RuleCondition]], # AND logic
    "conditions_any": Optional[List[RuleCondition]], # OR logic
    "stop_processing": Optional[bool] # If true, stop processing more rules for this row in this ruleset
})

RuleSet = List[Rule]


class HeuristicEngine:
    """
    A heuristic engine that loads rules from a YAML file and applies them
    to network flow data in a vectorized manner using Pandas.
    It tags flows by populating specified target columns based on rule conditions.
    """

    @staticmethod
    def _compile_regex(pattern: str) -> Tuple[str, int]:
        """Checks for (?i) prefix and returns pattern and flags."""
        flags = 0
        if pattern.startswith("(?i)"):
            pattern = pattern[4:]
            flags = re.IGNORECASE
        return pattern, flags

    OPERATORS: Dict[str, Callable[[pd.Series, Any], pd.Series]]

    def __init__(self, rules_path: str):
        """
        Initializes the HeuristicEngine with rules from the given YAML file.
        """
        self.rules_path = rules_path
        self.OPERATORS = {
            "equals": lambda series, value: series == value,
            "not_equals": lambda series, value: series != value,
            "in": lambda series, value_list: series.isin(value_list),
            "not_in": lambda series, value_list: ~series.isin(value_list),
            "regex": lambda series, pattern: series.astype(str).str.contains(
                *self._compile_regex(str(pattern)), regex=True, na=False
            ),
            "not_regex": lambda series, pattern: ~series.astype(str).str.contains(
                *self._compile_regex(str(pattern)), regex=True, na=False
            ),
            "cidr": lambda series, cidr_str: series.apply(
                lambda x: HeuristicEngine._is_ip_in_cidr(x, cidr_str) if pd.notna(x) else False
            ),
            "not_cidr": lambda series, cidr_str: ~series.apply(
                lambda x: HeuristicEngine._is_ip_in_cidr(x, cidr_str) if pd.notna(x) else False
            ),
            "gt": lambda series, value: pd.to_numeric(series, errors='coerce') > value,
            "lt": lambda series, value: pd.to_numeric(series, errors='coerce') < value,
            "gte": lambda series, value: pd.to_numeric(series, errors='coerce') >= value,
            "lte": lambda series, value: pd.to_numeric(series, errors='coerce') <= value,
            "exists": lambda series, _: series.notna(),
            "not_exists": lambda series, _: series.isna(),
            "starts_with": lambda series, prefix: series.astype(str).str.startswith(str(prefix), na=False),
            "ends_with": lambda series, suffix: series.astype(str).str.endswith(str(suffix), na=False),
        }
        self._load_and_parse_rules()

    def _load_and_parse_rules(self):
        """Loads and parses rules from the YAML file."""
        logger.info(f"Loading rules from: {self.rules_path}")
        self.rules_config: Dict[str, Any] = self._load_rules_config_file(self.rules_path)
        self.target_column_map: Dict[str, str] = self.rules_config.get("target_column_map", {})
        self.default_values: Dict[str, str] = self.rules_config.get("default_values", {})
        self.rule_sets: Dict[str, RuleSet] = {
            key: self.rules_config.get(key, []) for key in self.target_column_map.keys()
        }

        if not self.target_column_map:
            raise ValueError("Rules YAML must contain a 'target_column_map' section.")
        if not self.default_values and self.target_column_map:
            logger.warning("Rules YAML does not contain a 'default_values' section. "
                           "Target columns will be initialized with pd.NA if not set by rules.")
        logger.info("Rules loaded and parsed successfully.")

    def reload(self) -> None:
        """Reloads the rules from the YAML file."""
        logger.info(f"Reloading rules from: {self.rules_path}")
        try:
            self._load_and_parse_rules()
            logger.info("Rules reloaded successfully.")
        except Exception as e:
            logger.error(f"Failed to reload rules: {e}")
            # Optionally, decide if the old rules should be kept or cleared.
            # For now, if reload fails, the engine might be in an inconsistent state
            # or keep using old rules depending on how _load_and_parse_rules handles errors.
            # The current _load_and_parse_rules will raise, so the engine object won't be updated.

    @staticmethod
    def _is_ip_in_cidr(ip_str: str, cidr_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(str(ip_str))
            net = ipaddress.ip_network(str(cidr_str), strict=False)
            return ip in net
        except ValueError:
            return False
        except TypeError:
            return False

    def _load_rules_config_file(self, rules_path: str) -> Dict[str, Any]:
        try:
            with open(rules_path, 'r') as f:
                config = yaml.safe_load(f)
                if not isinstance(config, dict):
                    raise ValueError("Rules YAML root must be a dictionary.")
                return config
        except FileNotFoundError:
            logger.error(f"Rules file not found at {rules_path}")
            raise
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML rules from {rules_path}: {e}")
            raise ValueError(f"Error parsing YAML rules from {rules_path}: {e}")

    def _evaluate_conditions_list(self, df: pd.DataFrame, conditions: List[RuleCondition], logic_type: str) -> pd.Series:
        """Evaluates a list of conditions with specified logic (AND or OR)."""
        if not conditions:
            # For AND, no conditions means True. For OR, no conditions means False.
            return pd.Series([logic_type == "AND"] * len(df), index=df.index)

        final_mask_for_list = pd.Series([logic_type == "AND"] * len(df), index=df.index)

        for condition_idx, condition in enumerate(conditions):
            field = condition.get("field")
            operator_key = condition.get("operator")
            value = condition.get("value")

            current_condition_eval = pd.Series([False] * len(df), index=df.index) # Default to False

            if not field or not operator_key:
                logger.warning(f"Skipping invalid condition #{condition_idx+1} (missing field/operator): {condition}. Treated as False.")
            elif field not in df.columns:
                logger.warning(f"Field '{field}' in condition #{condition_idx+1} not found. Treated as False.")
            elif self.OPERATORS.get(operator_key) is None:
                logger.warning(f"Unsupported operator '{operator_key}' in condition #{condition_idx+1}. Treated as False.")
            else:
                operator_func = self.OPERATORS[operator_key]
                try:
                    current_condition_eval = operator_func(df[field], value)
                    if pd.api.types.is_object_dtype(current_condition_eval) or pd.api.types.is_bool_dtype(current_condition_eval):
                        current_condition_eval = current_condition_eval.fillna(False).astype(bool)
                    else:
                        current_condition_eval = current_condition_eval.astype(bool)
                except Exception as e:
                    logger.error(f"Error applying operator '{operator_key}' on field '{field}' (condition #{condition_idx+1}): {e}. Treated as False.")

            if logic_type == "AND":
                final_mask_for_list &= current_condition_eval
            elif logic_type == "OR":
                final_mask_for_list |= current_condition_eval

        return final_mask_for_list


    def _build_mask_for_rule(self, df: pd.DataFrame, rule: Rule) -> pd.Series:
        """Builds the final mask for a single rule, considering AND and OR conditions."""
        conditions_and = rule.get("conditions")
        conditions_or = rule.get("conditions_any")

        # Initialize masks based on whether condition lists are present
        mask_and = pd.Series([True] * len(df), index=df.index)
        if conditions_and is not None: # None means not present, empty list means evaluate as per _evaluate_conditions_list
             mask_and = self._evaluate_conditions_list(df, conditions_and, "AND")

        mask_or = pd.Series([False] * len(df), index=df.index) # Default to False for OR if not present
        if conditions_or is not None:
            mask_or = self._evaluate_conditions_list(df, conditions_or, "OR")

        # Combine AND and OR masks
        # If only one type of condition is present, the other mask is neutral
        # (all True for AND-part if conditions_and is None, all False for OR-part if conditions_any is None)
        if conditions_and is not None and conditions_or is not None:
            final_mask = mask_and & mask_or # Both present: AND the results of (AND_block) and (OR_block)
        elif conditions_and is not None:
            final_mask = mask_and # Only AND conditions
        elif conditions_or is not None:
            final_mask = mask_or # Only OR conditions
        else: # No conditions specified at all for the rule
            logger.warning(f"Rule '{rule.get('name')}' has no 'conditions' or 'conditions_any'. It will match all rows.")
            final_mask = pd.Series([True] * len(df), index=df.index) # Matches everything

        return final_mask


    def _apply_output_value(self, df: pd.DataFrame, mask: pd.Series,
                            target_column: str, rule: Rule) -> None:
        if not mask.any():
            return

        output_value = rule.get("output_value")
        output_value_format = rule.get("output_value_format")

        if output_value is not None:
            df.loc[mask, target_column] = output_value
        elif output_value_format is not None:
            placeholders = set(re.findall(r"\{(.*?)\}", output_value_format))
            relevant_columns = [col for col in placeholders if col in df.columns]

            if not relevant_columns and placeholders:
                logger.warning(
                    f"Rule '{rule.get('name')}': Placeholders in '{output_value_format}' "
                    f"not in DataFrame. Using literal string."
                )
                df.loc[mask, target_column] = output_value_format
                return

            if not placeholders: # No placeholders, treat as literal
                df.loc[mask, target_column] = output_value_format
                return

            def format_row(row_data: pd.Series) -> str:
                data_for_format = {k: str(v) if pd.notna(v) else "" for k, v in row_data.items()}
                try:
                    return output_value_format.format_map(data_for_format)
                except KeyError as e: # Should not happen if relevant_columns is built correctly
                    logger.error(f"KeyError during format_map for rule '{rule.get('name')}': {e}. Row data: {data_for_format}")
                    return output_value_format # Fallback to literal on error

            formatted_values = df.loc[mask, relevant_columns].apply(format_row, axis=1)
            df.loc[mask, target_column] = formatted_values
        else:
            logger.warning(f"Rule '{rule.get('name')}' has neither 'output_value' nor 'output_value_format'.")


    def tag_flows(self, flows_input: Union[List[Flow], pd.DataFrame]) -> pd.DataFrame:
        if isinstance(flows_input, pd.DataFrame):
            df = flows_input.copy() # Work on a copy if DataFrame is input
        elif isinstance(flows_input, list):
            if not flows_input:
                return pd.DataFrame()
            df = pd.DataFrame(flows_input)
        else:
            raise TypeError("Input must be a list of Flow TypedDicts or a Pandas DataFrame.")

        if df.empty:
            return pd.DataFrame()

        # Tracks rows that are "locked" by a "stop_processing: true" rule for each target column
        locked_rows_by_column: Dict[str, pd.Series] = {}

        for rule_group_key, target_column in self.target_column_map.items():
            default_val = self.default_values.get(target_column, pd.NA)
            df[target_column] = default_val
            locked_rows_by_column[target_column] = pd.Series([False] * len(df), index=df.index)

        for rule_group_key, rule_set in self.rule_sets.items():
            target_column = self.target_column_map.get(rule_group_key)
            if not target_column:
                logger.warning(f"No target column for rule group '{rule_group_key}'.")
                continue

            logger.info(f"Processing rules for target column: '{target_column}'")

            # Get the series tracking locked rows for the current target column
            locked_rows = locked_rows_by_column[target_column]

            for rule_config in rule_set:
                rule_name = rule_config.get("name", "Unnamed Rule")
                logger.debug(f"Applying rule: '{rule_name}'")

                # Build the mask for the current rule's conditions
                rule_match_mask = self._build_mask_for_rule(df, rule_config)

                # Rows to consider for this rule:
                # 1. Must match the rule's conditions (rule_match_mask)
                # 2. Must NOT be locked by a previous rule in this rule set (~locked_rows)
                effective_mask = rule_match_mask & ~locked_rows

                if effective_mask.any():
                    self._apply_output_value(df, effective_mask, target_column, rule_config)

                    # If this rule has "stop_processing: true", lock these rows for this target_column
                    if rule_config.get("stop_processing") is True:
                        locked_rows.loc[effective_mask] = True # Update the locked_rows series

        for target_column in self.target_column_map.values():
            if target_column in df.columns and df[target_column].isna().any():
                na_count = df[target_column].isna().sum()
                logger.warning(
                    f"Target column '{target_column}' has {na_count} NA "
                    f"value(s) after all rules were applied. These will remain as NA."
                )
        return df

def main_cli():
    parser = argparse.ArgumentParser(description="Tag flows using a heuristic engine and YAML rules.")
    parser.add_argument("--rules", required=True, help="Path to the YAML rules file.")
    parser.add_argument("--in", dest="input_file", required=True, help="Path to the input flow file (CSV, Parquet, JSON).")
    parser.add_argument("--out", dest="output_file", required=True, help="Path to save the tagged output file (CSV, Parquet, JSON).")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set the logging level.")

    args = parser.parse_args()

    # Set logging level from CLI argument
    logger.setLevel(args.log_level.upper())
    logger.info(f"Log level set to {args.log_level.upper()}")


    # Load input file
    input_path = args.input_file
    _, input_ext = os.path.splitext(input_path)
    input_ext = input_ext.lower()

    df_input: Optional[pd.DataFrame] = None
    logger.info(f"Reading input file: {input_path}")
    try:
        if input_ext == ".parquet":
            df_input = pd.read_parquet(input_path)
        elif input_ext == ".csv":
            df_input = pd.read_csv(input_path)
        elif input_ext == ".json":
            # Assuming JSON is a list of records (flows)
            df_input = pd.read_json(input_path, orient='records', lines=False) # Adjust orient/lines as needed
        else:
            logger.error(f"Unsupported input file extension: {input_ext}. Please use .parquet, .csv, or .json.")
            sys.exit(1)
        logger.info(f"Successfully read {len(df_input)} flows from {input_path}.")
    except Exception as e:
        logger.error(f"Error reading input file {input_path}: {e}")
        sys.exit(1)

    if df_input is None or df_input.empty:
        logger.warning("Input data is empty. Output will also be empty.")
        df_tagged = pd.DataFrame()
    else:
        # Initialize and run the engine
        try:
            engine = HeuristicEngine(rules_path=args.rules)
            df_tagged = engine.tag_flows(df_input)
            logger.info(f"Flow tagging complete. Output DataFrame has {len(df_tagged)} rows.")
        except Exception as e:
            logger.error(f"Error during heuristic engine processing: {e}")
            sys.exit(1)

    # Save output file
    output_path = args.output_file
    _, output_ext = os.path.splitext(output_path)
    output_ext = output_ext.lower()

    logger.info(f"Writing output file: {output_path}")
    try:
        if output_ext == ".parquet":
            df_tagged.to_parquet(output_path, index=False)
        elif output_ext == ".csv":
            df_tagged.to_csv(output_path, index=False)
        elif output_ext == ".json":
            # Outputting as JSON records
            df_tagged.to_json(output_path, orient='records', indent=2, lines=False) # Adjust orient/lines/indent
        else:
            logger.error(f"Unsupported output file extension: {output_ext}. Please use .parquet, .csv, or .json.")
            sys.exit(1)
        logger.info(f"Successfully wrote tagged flows to {output_path}.")
    except Exception as e:
        logger.error(f"Error writing output file {output_path}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main_cli()
