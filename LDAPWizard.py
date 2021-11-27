from dataclasses import dataclass
from datetime import timedelta, datetime, timezone
from typing import Tuple, List, Union, Dict
import logging

import ldap

logger = logging.getLogger(__name__)

EPOCH_TIMESTAMP = 116444736000000000

def windows_timestamp_to_datetime(timestamp: int) -> datetime:
    """ Convert Windows timestamp to datetime – because *Microsoft* """
    nanoseconds = (timestamp - EPOCH_TIMESTAMP) // 10
    dt = datetime(1970, 1, 1) + timedelta(microseconds=nanoseconds)
    return dt.replace(tzinfo=timezone.utc)


class LDAPException(Exception):
    pass


@dataclass
class LDAPWizard:
    LDAP_USER = settings.AUTH_LDAP_BIND_DN
    LDAP_PASSWORD = settings.AUTH_LDAP_BIND_PASSWORD
    LDAP_SERVER = settings.AUTH_LDAP_QUERY_SERVER_URI
    connection: 'ldap.ldapobject.SimpleLDAPObject' = None
    debug: bool = False

    def __post_init__(self):
        if not self.connection: self.connection = self.login()

    def login(self) -> 'ldap.ldapobject.SimpleLDAPObject':
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        ldap.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        ldap.set_option(ldap.OPT_X_TLS_DEMAND, True)
        if (self.debug): ldap.set_option(ldap.OPT_DEBUG_LEVEL, 255)

        logger.debug(f'Attempting to login LDAP user {self.LDAP_USER}',)
        try:
            if not self.LDAP_USER or not self.LDAP_PASSWORD: raise ldap.INVALID_CREDENTIALS

            l = ldap.initialize(self.LDAP_SERVER)
            l.simple_bind_s(self.LDAP_USER, self.LDAP_PASSWORD)
            logger.info(f'User {self.LDAP_USER} logged in successfully to query Active Directory server "{self.LDAP_SERVER}"')
            return l

        except ldap.INVALID_CREDENTIALS as e:
            logger.exception(f'LDAP Authentication failed for user {self.LDAP_USER}')
            raise LDAPException('AD Credentials invalid or user locked out.') from None

        except ldap.SERVER_DOWN as e:
            logger.exception(f'Cannot reach LDAP server "{self.LDAP_SERVER}"')
            raise LDAPException(f'AD server "{self.LDAP_SERVER}" unreachable.') from None

    def logout(self) -> bool:
        self.connection.unbind_s()
        logger.debug(f'Logout successful for user {self.LDAP_USER}')
        return True

    def search(self, object_dn: str, criteria: str=None) -> List[Tuple]:
        """ Searches everything within a given OU. Objects can be filtered down by applying objectClass.
        Afterwards it will display all defined attributes. Sample arguments:

        object_dn: 'ou=Gruppen,dc=sys,dc=loc'
        objectClass: *, group, computer, user, ...
        """

        logger.debug(f'Querying LDAP for {object_dn}, {criteria}')
        criteria = criteria or '(objectClass=*)'

        try:
            r = self.connection.search_s(object_dn, ldap.SCOPE_SUBTREE, criteria)

            for dn, entry in r:
                logger.debug(f'Processing {repr(dn)}')
                logger.debug(entry)

            return r

        except ldap.INSUFFICIENT_ACCESS:
            logger.exception(f'Insufficient access for user {self.LDAP_USER}, querying all values {object_dn}, {criteria}')
            raise LDAPException('Insufficient access.') from None

        except ldap.NO_SUCH_OBJECT:
            logger.error(f'Requested object does not exist for querying {object_dn}, {criteria}')
            raise LDAPException(f'Object not found or does not exist "{object_dn}"')

    def get_users(self) -> List[Tuple[str, str]]:
        """ Returns a list of distinguishedNames and sAMAccountNames in the defined BASE_DN and SEARCH_CRITERIA """
        users = self.search(
            object_dn=settings.AUTH_LDAP_USER_SEARCH.base_dn,
            criteria=settings.LDAP_SEARCH_USER_CRITERIA
        )
        formatted_users = []
        for distinguished_name, user in users:
            sam_account_name = user.get('sAMAccountName')[0].decode()
            formatted_users.append((distinguished_name, sam_account_name))

        return formatted_users

    def get_attribute(self, object_dn: str, attributes: List[str], criteria: str=None) -> Dict[str, Union[list, str, int, None]]:
        """ Gets the {attribute}-value of a given {object_dn}. Depending on the
        attribute's data-type in AD DS returns either a list, str or int """

        logger.debug(f'Querying LDAP for {object_dn}: {attributes}')

        instance = self.search(object_dn=object_dn, criteria=criteria)
        if len(instance) > 1:
            logger.error(f'Multiple instances returned for {object_dn}')
            return {}  # more than one object-instance

        info = {}
        for attribute in attributes:
            value = instance[0][1].get(attribute)

            if isinstance(value, list) and len(value) > 1:
                info.setdefault(attribute, [i.decode() for i in value])
            elif isinstance(value, list):
                value = value[0].decode()
                if value.isdigit(): value = int(value)
                info.setdefault(attribute, value)
            else:
                info.setdefault(attribute, value)

        return info

    def get_groups(self, search_ou: str):
        """ Arbitrary function that gets all Groups from {object_dn}
        and returns a mapped dict {'groupName': 'CN=...'}. """
        processed_groups = {}
        groups = self.search(search_ou, criteria='(objectClass=Group)')

        for dn, group in groups:
            cn = group['cn'][0].decode('utf-8')
            dn = group['distinguishedName'][0].decode('utf-8')
            processed_groups[cn] = dn

        logger.debug(f'Processed groups: {processed_groups}')
        return processed_groups



@dataclass
class LDAPUser:
    """ Class to evaluate userAccountControl state for the various properties it can take
    REF: http://www.selfadsi.org/ads-attributes/user-userAccountControl.htm """
    username: str
    distinguished_name: str
    user_account_control: int  # decimal representation like in AD DS (e.g. 512)

    @property
    def user_account_control_binary(self):
        """ Converts decimal to binary 512 -> 00000000000000000000001000000000 """
        binary = bin(self.user_account_control)[2:]
        return binary.zfill(32)

    @property
    def account_ok(self) -> bool:
        return self.normal_account and \
               not self.is_disabled and \
               not self.is_locked_out and \
               not self.password_expired

    @property
    def normal_account(self) -> bool:
        return self.binary_position(23) == 1 and \
               not self.workstation_trust_account and \
               not self.interdomain_trust_account and \
               not self.server_trust_account

    @property
    def is_disabled(self) -> bool:
        return self.binary_position(31) == 1

    @property
    def is_locked_out(self) -> bool:
        """ Checks if a user is locked out according to userAccountControl """
        return self.binary_position(28) == 1

    @property
    def password_dont_expire(self) -> bool:
        return self.binary_position(16) == 1

    @property
    def password_expired(self) -> bool:
        return self.binary_position(9) == 1

    @property
    def password_not_required(self) -> bool:
        return self.binary_position(27) == 1

    @property
    def cant_change_password(self) -> bool:
        return self.binary_position(26) == 1

    @property
    def smartcard_required(self) -> bool:
        return self.binary_position(14) == 1

    @property
    def interdomain_trust_account(self) -> bool:
        return self.binary_position(21) == 1

    @property
    def workstation_trust_account(self) -> bool:
        return self.binary_position(20) == 1

    @property
    def server_trust_account(self) -> bool:
        return self.binary_position(19) == 1

    def binary_position(self, pos: int) -> int:
        return int(self.user_account_control_binary[pos-1])

    @property
    def groups(self) -> List[str]:
        return self.get_attribute('memberOf')

    def get_attribute(self, attribute: str) -> Union[list, str, int, None]:
        """ Helper function to get a certain user's attribute """
        ldap_wizard = LDAPWizard()
        ldap_attribute = ldap_wizard.get_attribute(
            object_dn=self.distinguished_name,
            attributes=[attribute]
        )
        return ldap_attribute.get(attribute)

    @classmethod
    def from_distinguished_name(cls, distinguished_name):
        ldap_wizard = LDAPWizard()
        user_info = ldap_wizard.get_attribute(
            object_dn=distinguished_name,
            attributes=['sAMAccountName', 'userAccountControl'],
            criteria='(objectClass=User)'
        )
        user = cls(
            username=user_info.get('sAMAccountName'),
            distinguished_name=distinguished_name,
            user_account_control=user_info.get('userAccountControl')
        )
        return user

    @classmethod
    def from_sam_account_name(cls, sam_account_name):
        ldap_wizard = LDAPWizard()
        user_info = ldap_wizard.get_attribute(
            object_dn=settings.AUTH_LDAP_USER_SEARCH.base_dn,
            attributes=['distinguishedName', 'userAccountControl'],
            criteria=f'(sAMAccountName={sam_account_name})'
        )
        user = cls(
            username=sam_account_name,
            distinguished_name=user_info.get('distinguishedName'),
            user_account_control=user_info.get('userAccountControl')
        )
        return user
