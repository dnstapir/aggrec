import os
import pathlib

import yaml

OPENAPI_YAML_FILENAME = pathlib.Path(os.path.abspath(__file__)).parent / "openapi.yaml"
OPENAPI_DICT = yaml.load(open(OPENAPI_YAML_FILENAME).read(), Loader=yaml.SafeLoader)
