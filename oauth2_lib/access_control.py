from __future__ import annotations

from abc import ABCMeta, abstractmethod
from functools import reduce
from typing import Any, List, Tuple


class InvalidRuleDefinition(Exception):
    def __str__(self):
        return "{} (rule {}):\n{}".format(*self.args)


class AbstractCondition(object, metaclass=ABCMeta):
    """Abstract class definition for access control conditions."""

    @classmethod
    def concrete_condition(klass, name, options):
        subclasses = {subclass.__name__: subclass for subclass in klass.__subclasses__()}
        my_condition = subclasses[name](options)
        return my_condition

    @abstractmethod
    def __init__(self, options: Any) -> None:
        pass

    @abstractmethod
    def __str__(self) -> str:
        pass

    @abstractmethod
    def test(self, user_attributes, current_request) -> bool:
        pass


class TargetOrganizations(AbstractCondition):
    URN = "urn:mace:surfnet.nl:surfnet.nl:sab:organizationCode:"
    institutions = [1, 2, 3, 4, 9, 14, 18, 19, 22, 23, 24]
    service_providers = [11, 26]
    international_partners = [13]
    colo_providers = [6, 10]
    other = [5, 7, 8, 11, 12, 15, 16, 17, 20, 21, 25, 27, 28, 29, 30, 31, 32, 100]

    valid = {
        "institutions": institutions,
        "service_providers": service_providers,
        "international_partners": international_partners,
        "colo_providers": colo_providers,
        "other": other,
    }

    def __init__(self, options):
        self.target_organizations = reduce(set.union, (set(self.valid[option]) for option in options))

    def __str__(self):
        return f"CODE in {self.URN}CODE in eduperson_entitlements should be one of {sorted(self.target_organizations)}"

    def test(self, user_attributes, current_request):
        return bool(user_attributes.organization_codes & self.target_organizations)


class SABRoles(AbstractCondition):
    URN = "urn:mace:surfnet.nl:surfnet.nl:sab:role:"
    infrabeheerder = "Infrabeheerder"
    infraverantwoordelijke = "Infraverantwoordelijke"
    superuserro = "SuperuserRO"

    valid = {
        "infrabeheerder": infrabeheerder,
        "infraverantwoordelijke": infraverantwoordelijke,
        "Infrabeheerder": infrabeheerder,
        "Infraverantwoordelijke": infraverantwoordelijke,
        "SuperuserRO": superuserro,
        "superuserro": superuserro,
    }

    def __init__(self, options):
        self.roles = {self.valid[option] for option in options}

    def __str__(self):
        return f"ROLE in {self.URN}ROLE in eduperson_entitlements should be one of {self.roles}"

    def test(self, user_attributes, current_request):
        return bool(user_attributes.roles & self.roles)


class Teams(AbstractCondition):
    URN = "urn:collab:group:surfteams.nl:nl:surfnet:diensten:"

    admins = "automation-admins"
    changes = "network-changes"
    fls = "noc-fls"
    lir = "network-lir"
    noc = "noc-engineers"
    readonly = "automation-read-only"
    superuserro = "noc_superuserro_team_for_netwerkdashboard"
    support = "customersupport"
    ten = "ten"

    valid = {
        "admins": admins,
        "automation-admins": admins,
        "automation-read-only": readonly,
        "customersupport": support,
        "fls": fls,
        "klantsupport": support,
        "lir": lir,
        "network-changes": changes,
        "network-lir": lir,
        "noc": noc,
        "noc-engineers": noc,
        "noc-fls": fls,
        "readonly": readonly,
        "superuserro": superuserro,
        "support": support,
        "ten": ten,
    }

    def __init__(self, options):
        self.teams = {self.valid[option] for option in options}

    def __str__(self):
        return f"TEAM in {self.URN}TEAM should be one of {self.teams}"

    def test(self, user_attributes, current_request):
        return bool(user_attributes.teams & self.teams)


class Scopes(AbstractCondition):
    def __init__(self, options):
        self.scopes = set(options)

    def __str__(self):
        return f"Scope must be one of the following: {self.scopes}"

    def test(self, user_attributes, current_request):
        return bool(user_attributes.scopes & self.scopes)


class AnyOf(AbstractCondition):
    def __init__(self, options):
        self.conditions = [
            AbstractCondition.concrete_condition(name, suboptions) for name, suboptions in options.items()
        ]

    def __str__(self):
        lst = "\n".join(str(c) for c in self.conditions)
        return f"Any of the following conditions should apply:\n{lst}"

    def test(self, user_attributes, current_request):
        return True in (condition.test(user_attributes, current_request) for condition in self.conditions)


class AllOf(AbstractCondition):
    def __init__(self, options):
        self.conditions = [
            AbstractCondition.concrete_condition(name, suboptions) for name, suboptions in options.items()
        ]

    def __str__(self):
        lst = "\n".join(str(c) for c in self.conditions)
        return f"All of the following conditions should apply:\n{lst}"

    def test(self, user_attributes, current_request):
        return False not in (condition.test(user_attributes, current_request) for condition in self.conditions)


class OrganizationGUID(AbstractCondition):
    URN = "urn:mace:surfnet.nl:surfnet.nl:sab:organizationGUID:"
    valid = {"path", "query", "json"}

    def __init__(self, options):
        assert options["where"] in self.valid, f"The 'where' option should be one of {self.valid}"
        self.where = options["where"]
        self.param = options["parameter"]

    def __str__(self):
        return f"Parameter {self.param} in the request {self.where} should be in your organization GUID ('{self.URN}')"

    def test(self, user_attributes, current_request):
        if self.where == "path":
            return current_request.view_args.get(self.param) in user_attributes.organization_guids
        if self.where == "query":
            return current_request.args.get(self.param) in user_attributes.organization_guids
        if self.where == "json":
            json = current_request.json
            if json is None:
                # Let the application handle the bad json request
                return True
            return json.get(self.param) in user_attributes.organization_guids


Rules = List[Tuple[str, List[str], AbstractCondition]]
