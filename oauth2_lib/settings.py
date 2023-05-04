# Copyright 2019-2023 SURF.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from pydantic import BaseSettings


class Oauth2LibSettings(BaseSettings):
    """Common settings for applications depending on oauth2-lib."""

    ENVIRONMENT: str = "local"
    SERVICE_NAME: str = ""
    MUTATIONS_ENABLED: bool = False
    ENVIRONMENT_IGNORE_MUTATION_DISABLED: list[str] = []
    OAUTH2_ACTIVE: bool = False


oauth2lib_settings = Oauth2LibSettings()
