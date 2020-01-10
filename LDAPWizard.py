import logging
logger = logging.getLogger(__name__)

class LDAPWizard:
    LDAP_SRV = get_env_value['LDAP_SERVER']
    LDAP_SUPER_USER = get_env_value('LDAP_SUPER_USER')

    def __init__(self, ldap_user=None, ldap_pwd=None, ldap_srv=None, debug=False, user='SYSTEM'):
        """ Initializes LDAP connection object. Server MUST be ldaps, otherwise some actions
        like password changes are declined by the server. (ERROR: UNWILLING TO PERFORM) """
        self.ldap_user = ldap_user or ''
        self.ldap_pwd = ldap_pwd or ''
        self.ldap_srv = ldap_srv or self.LDAP_SRV
        self.debug = debug or False
        self.user = user

        self.connection = self.login()

    @classmethod
    def super_user(cls, debug=False):
        """ User used to alter Active Directory with minimal privileges. """
        logger.debug('Logging in as LDAP super user...', extra={'user': self.user})
        ldap_user = self.LDAP_SUPER_USER
        ldap_pwd = get_env_value('LDAP_SUPER_PASSWORD')
        ldap_srv = get_env_value('LDAP_SERVER')

        return cls(ldap_user, ldap_pwd, ldap_srv, debug)

    def login(self):

        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        ldap.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        ldap.set_option(ldap.OPT_X_TLS_DEMAND, True)
        if(self.debug):
            ldap.set_option(ldap.OPT_DEBUG_LEVEL, 255)

        logger.debug(f'Attempting to login LDAP user {self.ldap_user}', extra={'user': self.user, 'uid': self.ldap_user})
        try:
            if(self.ldap_user == '' or self.ldap_pwd == '' or self.ldap_user is None or self.ldap_pwd is None):
                raise ldap.INVALID_CREDENTIALS

            l = ldap.initialize(self.ldap_srv)
            l.simple_bind_s(self.ldap_user, self.ldap_pwd)
            logger.info(f'User {self.ldap_user} logged in successfully to propagate Active Directory changes.', extra={'user': self.user, 'uid': self.ldap_user})
            return l

        except ldap.INVALID_CREDENTIALS as e:

            if(self.ldap_user != self.LDAP_SUPER_USER):
                x = LDAPWizard.super_user()
                if(x.active_lockout(self.ldap_user)):
                    logger.error(f'LDAP login refused due to user lockout {self.ldap_user}', extra={'user': self.user, 'uid': self.ldap_user})
                    raise Exception('User lockout active.') from None

                elif(x.expired_password(self.ldap_user)):
                    logger.error(f'LDAP login refused due to user password expiration {self.ldap_user}', extra={'user': self.user, 'uid': self.ldap_user})
                    raise Exception('User password expired.') from None
                else:
                    logger.error(f'Invalid credentials for user {self.ldap_user} during LDAP login.', extra={'user': self.user, 'uid': self.ldap_user})
                    raise Exception('User or password invalid.') from None

            else:
                logger.exception('Could not login to LDAP login with super user.', extra={'user': self.user, 'uid': self.ldap_user})
                raise Exception('Please contact your Administrator. Degraded system functionality.') from None

        except ldap.SERVER_DOWN as e:
            logger.error(f'Cannot reach LDAP server {self.ldap_srv}', extra={'user': self.user, 'uid': self.ldap_user})
            raise Exception('Server unreachable.') from None
        except Exception as e:
            logger.exception(str(e), extra={'user': self.user})
            raise Exception('An unknown error occurred.') from None

    def logout(self):
        self.connection.unbind_s()
        logger.debug(f'User {self.ldap_user} logged out.', extra={'user': self.user, 'uid': self.ldap_user})

    def set_attribute_value(self, object_dn, attribute, value):
        """ Helper function that adds a value if, the attribute is string. 

        CAUTION: May cause SERIOUS problems, if DNs of users/groups/computers include ';' in name
        """
        if(';' in value):
            logger.debug(f'value: {value} must not contain ";" for add_attribute_value_str.', extra={'user': self.user, 'uid': object_dn})
            raise Exception('Illegal value.') from None

        try:
            mod_attrs = [(ldap.MOD_REPLACE, attribute, [value.encode('utf-8')])]
            self.connection.modify_s(object_dn, mod_attrs)
            logger.info(f'Successfully added value {attribute}: {value} ({object_dn})', extra={'user': self.user, 'uid': object_dn})
        except ldap.INSUFFICIENT_ACCESS as e:
            logger.error(f'Insufficient access for user {self.ldap_user}, adding value {attribute}: {value} ({object_dn})', extra={'user': self.user, 'uid': self.ldap_user})
            raise Exception('Insufficient access.') from None
        except ldap.NO_SUCH_OBJECT as e:
            logger.error(f'Requested object does not exist for adding {attribute}: {value} ({object_dn})', extra={'user': self.user, 'uid': object_dn})
            raise Exception('Object not found.') from None
        except Exception as e:
            logger.exception(str(e), extra={'user': self.user, 'uid': object_dn})
            raise Exception('An unknown error occurred.') from None

    def add_attribute_value_str(self, object_dn, attribute, value):
        """ Helper function that adds a value if, the attribute is string. 

        CAUTION: May cause SERIOUS problems, if DNs of users/groups/computers include ';' in name
        """
        if(';' in value):
            logger.debug(f'value: {value} must not contain ";" for add_attribute_value_str.')
            raise Exception('Illegal value.') from None

        _value = self.get_attribute_value(object_dn, attribute)

        logger.debug(f'Found values {attribute}: {_value} ({object_dn})', extra={'user': self.user, 'uid': object_dn})

        if(value in _value):
            logger.error(f'value {attribute}: {value} already in values {_value} ({object_dn})', extra={'user': self.user, 'uid': object_dn})
            raise Exception('Value already present.') from None
        elif isinstance(_value, list):
            # convert list to ';'-delimited string
            _value = '; '.join(_value)
        else:
            # do nothing lol
            _value = _value

        try:
            _value = '{}; {}'.format(_value, value)
            mod_attrs = [(ldap.MOD_REPLACE, attribute, [_value.encode('utf-8')])]
            self.connection.modify_s(object_dn, mod_attrs)
            logger.info(f'Successfully added value {attribute}: {value} ({object_dn})', extra={'user': self.user, 'uid': object_dn})
        except ldap.INSUFFICIENT_ACCESS as e:
            logger.error(f'Insufficient access for user {self.ldap_user}, adding value {attribute}: {value} ({object_dn})', extra={'user': self.user, 'uid': self.ldap_user})
            raise Exception('Insufficient access.') from None
        except ldap.NO_SUCH_OBJECT as e:
            logger.error(f'Requested object does not exist for adding {attribute}: {value} ({object_dn})', extra={'user': self.user, 'uid': object_dn})
            raise Exception('Object not found.') from None
        except Exception as e:
            logger.exception(str(e), extra={'user': self.user, 'uid': object_dn})
            raise Exception('An unknown error occurred.') from None

    def add_attribute_value(self, object_dn, attribute, value):
        """
        Adds a {value} to an {attribute} of a given {object_dn}. It is expected
        that the {attribute}-field is list at first. In case it is a string the
        exception handles said case.
        """
        if(';' in value):
            logger.debug(f'value: {value} must not contain ";" for add_attribute_value_str.', extra={'user': self.user, 'uid': object_dn})
            raise Exception('Illegal value.') from None

        try:
            logger.debug(f'ADD ({object_dn}) {attribute}: {value}', extra={'user': self.user, 'uid': object_dn})
            add_attrs = [(ldap.MOD_ADD, attribute, [value.encode('utf-8')])]
            self.connection.modify_s(object_dn, add_attrs)
            logger.info(f'Successfully added value {attribute}: {value} ({object_dn})', extra={'user': self.user, 'uid': object_dn})

        # If this error is thrown, the attribute is likely a string and is therefore modified
        #   by appending {value} to the already existing string.
        except ldap.TYPE_OR_VALUE_EXISTS as e:
            logger.info(f'Value for {attribute} ({object_dn}) already exists. Trying', extra={'user': self.user, 'uid': object_dn})
            self.add_attribute_value_str(object_dn, attribute, value)

        except ldap.INSUFFICIENT_ACCESS as e:
            logger.error(f'Insufficient access for user {self.ldap_user}, adding value {attribute}: {value} ({object_dn})', extra={'user': self.user, 'uid': self.ldap_user})
            raise Exception('Insufficient access.') from None
        except ldap.NO_SUCH_OBJECT as e:
            logger.error(f'Requested object does not exist for adding {attribute}: {value} ({object_dn})', extra={'user': self.user, 'uid': object_dn})
            raise Exception('Object not found.') from None
        except Exception as e:
            logger.exception(str(e), extra={'user': self.user, 'uid': object_dn})
            raise Exception('An unknown error occurred.') from None

    def remove_attribute_value_str(self, object_dn, attribute, value):
        """ Helper function that removes a value if, the attribute is string. 

        CAUTION: May cause SERIOUS problems, if DNs of users/groups/computers include ';' in name
        """
        if(';' in value):
            logger.debug(f'value: {value} must not contain ";" for add_attribute_value_str.', extra={'user': self.user, 'uid': object_dn})
            raise Exception('Illegal value.') from None

        _value = self.get_attribute_value(object_dn, attribute)

        logger.debug(f'Found values {attribute}: {_value} ({object_dn})', extra={'user': self.user, 'uid': object_dn})

        if(value not in _value):
            logger.error(f'Value {attribute}: {value} not in values {_value} ({object_dn})', extra={'user': self.user, 'uid': object_dn})
            raise Exception('Illegal value.') from None

        elif isinstance(_value, list):
            # convert list to ';'-delimited string after removing value
            _value.remove(value)
            _value = '; '.join(_value)
        else:
            _value = None

        try:
            mod_attrs = [(ldap.MOD_REPLACE, attribute, [_value.encode('utf-8')])]
            self.connection.modify_s(object_dn, mod_attrs)
            logger.info(f'Successfully removed value {attribute}: {value} ({object_dn})')
        except ldap.INSUFFICIENT_ACCESS as e:
            logger.error(f'Insufficient access for user {self.ldap_user}, removing value {attribute}: {value} ({object_dn})', extra={'user': self.user, 'uid': self.ldap_user})
            raise Exception('Insufficient access.') from None
        except ldap.NO_SUCH_OBJECT as e:
            logger.error(f'Requested object does not exist for removing {attribute}: {value} ({object_dn})', extra={'user': self.user, 'uid': object_dn})
            raise Exception('Object not found.') from None
        except Exception as e:
            logger.exception(str(e), extra={'user': self.user, 'uid': object_dn})
            raise Exception('An unknown error occurred.') from None

    def remove_attribute_value(self, object_dn, attribute, value):
        """ Removes a {value} of an {attribute} of a given {object_dn}. It is expected 
        that the {attribute}-field is list at first. In case it is a string the
        exception handles said case.
        """
        if(';' in value):
            logger.debug(f'value: {value} must not contain ";" for add_attribute_value_str.', extra={'user': self.user, 'uid': object_dn})
            raise Exception('Illegal value.') from None

        try:
            logger.debug(f'DELETE ({object_dn}) {attribute}: {value}', extra={'user': self.user, 'uid': object_dn})
            delete_attrs = [(ldap.MOD_DELETE, attribute, [value.encode('utf-8')])]
            self.connection.modify_s(object_dn, delete_attrs)
            logger.info(f'Successfully removed value {attribute}: {value} ({object_dn})', extra={'user': self.user, 'uid': object_dn})

        # If this error is thrown, the attribute is likely a string and is therefore modified
        #   by appending {value} to the already existing string.
        except ldap.NO_SUCH_ATTRIBUTE as e:
            logger.info(f'Value for {attribute} ({object_dn}) could not be deleted.', extra={'user': self.user, 'uid': object_dn})
            self.remove_attribute_value_str(object_dn, attribute, value)

        except ldap.INSUFFICIENT_ACCESS as e:
            logger.error(f'Insufficient access for user {self.ldap_user}, removing value {attribute}: {value} ({object_dn})', extra={'user': self.user, 'uid': self.ldap_user})
            raise Exception('Insufficient access.') from None
        except ldap.NO_SUCH_OBJECT as e:
            logger.error(f'Requested object does not exist for removing {attribute}: {value} ({object_dn})', extra={'user': self.user, 'uid': object_dn})
            raise Exception('Object not found.') from None
        except Exception as e:
            logger.exception(str(e), extra={'user': self.user, 'uid': object_dn})
            raise Exception('An unknown error occurred.') from None

    def get_attribute_value(self, object_dn, attribute):
        """ Gets an {attribute}-value of a given {object_dn}. 
        Returns either a list of objects or a byte-list of objects, depending on
            the attribute's datatype in Active Directory.
        """
        logger.debug(f'Querying LDAP for {object_dn}: {attribute} with user: {self.ldap_user})', extra={'user': self.user, 'uid': object_dn})
        try:
            r = self.connection.search_s(object_dn, ldap.SCOPE_SUBTREE, '(objectClass=*)', [attribute])
            if(attribute in r[0][1].keys()):
                if(len(r[0][1][attribute]) == 1):
                    value = r[0][1][attribute][0].decode('utf-8')
                    # Makes list out of attributes, if there should be multiple values
                    if(';' in value):
                        value = value.replace('; ', ';')
                        values = value.split(';')
                        return values
                    else:
                        return value
                else:
                    return r[0][1][attribute]
            else:
                logger.error(f'Attribute {object_dn}: {attribute} does not exist.', extra={'user': self.user, 'uid': object_dn})
                raise Exception('Requested attribute could not be retrieved or empty.') from None
        except ldap.INSUFFICIENT_ACCESS as e:
            logger.error(f'Insufficient access for user {self.ldap_user}, retrieving attribute {object_dn}: {attribute}', extra={'user': self.user, 'uid': self.ldap_user})
            raise Exception('Insufficient access.') from None
        except ldap.NO_SUCH_OBJECT as e:
            logger.error(f'Requested object does not exist have attribute {object_dn}: {attribute}', extra={'user': self.user, 'uid': object_dn})
            raise Exception('Object not found.') from None
        except Exception as e:
            logger.exception(str(e), extra={'user': self.user, 'uid': object_dn})
            raise Exception('An unknown error occurred.') from None

    def search_base_dn(self, object_dn, attributes=['distinguishedName', 'extensionAttribute14'], objectClass='*'):
        """ Searches everything within a given OU. Objects can be filtered down by applying objectClass.
            Afterwards it will display all defined attributes.

        object_dn:
            'ou=Gruppen,dc=sys,dc=loc'

        objectClass:
            *, group, computer, user, ...
        """
        logger.debug(f'Querying LDAP for {object_dn}: {attributes}, objectClass="{objectClass}" (User: {self.ldap_user})')

        try:
            r = self.connection.search_s(object_dn, ldap.SCOPE_SUBTREE, f'(objectClass={objectClass})', attributes)
            for dn, entry in r:
                logger.debug('Processing', repr(dn))
                logger.debug(entry)
            return r
        except ldap.INSUFFICIENT_ACCESS as e:
            logger.error(f'Insufficient access for user {self.ldap_user}, querying all values {object_dn}: {attributes}, objectClass="{objectClass}")', extra={'user': self.user, 'uid': self.ldap_user})
            raise Exception('Insufficient access.') from None
        except ldap.NO_SUCH_OBJECT as e:
            logger.error(f'Requested object does not exist for querying {object_dn}: {attributes}, objectClass="{objectClass}")', extra={'user': self.user, 'uid': object_dn})
            raise Exception('Object not found.') from None
        except Exception as e:
            logger.exception(str(e), extra={'user': self.user, 'uid': object_dn})
            raise Exception('An unknown error occurred.') from None

    def change_password(self, new_password, old_password=None, user_dn=None):
        """ Change user password. In order to do so we require both the current and the new
        password of the affected user, if we're not dealing w/ a privileged AD user. """

        if(user_dn != None and old_password == None):
            logger.info(f'Invoked password change for {user_dn}...', extra={'user': self.user, 'uid': user_dn})

            new_pwd = '"{0}"'.format(new_password).encode('utf-16-le')
            mod_list = [
                (ldap.MOD_REPLACE, "unicodePwd", new_pwd),
            ]
        else:
            user_dn = user_dn or self.ldap_user
            old_password = old_password or self.ldap_pwd

            logger.info(f'Password change for {user_dn}...', extra={'user': self.user, 'uid': user_dn})
            old_pwd = '"{0}"'.format(old_password).encode('utf-16-le')
            new_pwd = '"{0}"'.format(new_password).encode('utf-16-le')

            mod_list = [
                (ldap.MOD_DELETE, "unicodePwd", old_pwd),
                (ldap.MOD_ADD, "unicodePwd", new_pwd),
            ]

        try:
            self.connection.modify_s(user_dn, mod_list)
        except ldap.INSUFFICIENT_ACCESS as e:
            logger.error(f'Insufficient access to change {user_dn} password with user: {self.ldap_user}', extra={'user': self.user, 'uid': self.ldap_user})
            raise Exception('Insufficient access.') from None
        except ldap.CONSTRAINT_VIOLATION as e:
            logger.error(f'Password change for {user_dn} does not meet server criteria (complexity, length, history, ...)', extra={'user': self.user, 'uid': user_dn})
            raise Exception('Password requirements not met. Passwords must not contain part of the username, must have '
                            'lower- and upper case letters and must not be a previously used password. Further requirements may apply. '
                            'Please try again using a different password or contact your Administrator.') from None

    def get_group_dns(self, object_dn):
        """ Arbitrary function that gets all Groups from {object_dn}
        and returns a mapped dict {'groupName': 'CN=...'}. """
        processed_groups = {}
        groups = self.search_base_dn(object_dn, objectClass='Group', attributes=['distinguishedName', 'cn'])

        for dn, group in groups:
            cn = group['cn'][0].decode('utf-8')
            dn = group['distinguishedName'][0].decode('utf-8')
            processed_groups[cn] = dn

        logger.debug(f'Processed groups: {processed_groups}', extra={'user': self.user, 'uid': object_dn})
        return processed_groups

    def add_user_group(self, group_dn, user_dn):
        """ Adds a given user to a group.
        Expects user_dn, e.g. CN=Service User,OU=Mitarbeiter,DC=sys,DC=loc
        Expects group_dn e.g. CN=Test Group,OU=Gruppen,DC=sys,DC=loc

        Alternativer Ansatz:
            add_attrs = [(ldap.MOD_ADD, 'member', [user_dn.encode('utf-8')])]
            r = l.modify_s(group_dn, add_attrs)
            return 'success'
        """
        logger.info(f'Adding user {user_dn} to group {group_dn}', extra={'user': self.user, 'uid': group_dn})
        self.add_attribute_value(group_dn, 'member', user_dn)

    def remove_user_group(self, group_dn, user_dn):
        """ Removes a given user to a group.
        Expects user_dn, e.g. CN=Service User,OU=Mitarbeiter,DC=sys,DC=loc
        Expects group_dn e.g. CN=Test Group,OU=Gruppen,DC=sys,DC=loc
        """
        logger.info(f'Removing user {user_dn} from group {group_dn}', extra={'user': self.user, 'uid': group_dn})
        self.remove_attribute_value(group_dn, 'member', user_dn)
        #delete_attrs = [(ldap.MOD_DELETE, 'member', [user_dn.encode('utf-8')])]
        #l.modify_s(group_dn, delete_attrs)

    def user_status(self, user_dn):
        """ userAccountControl status overview
            == 512 enabled user
            == 514 disabled (+2) 
            == 528 lockout (+16)
            == 66048 dont expire pwd (+64)
            == 8389120 (pwd expired)

            === 4096 enabled computer
        https://support.microsoft.com/en-us/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties
        """
        status = self.search_base_dn(base_dn=user_dn, attributes=['userAccountControl'], objectClass='user')
        return status[0][1]['userAccountControl'][0].decode('utf-8')

    def expired_password(self, user_dn):
        """ Evaluates if a password has expired. """
        pwdLastSet = self.search_base_dn(base_dn=user_dn, attributes=['pwdLastSet'], objectClass='user')
        if(pwdLastSet[0][1]['pwdLastSet'][0].decode('utf-8') == '0' or self.user_status(user_dn) == 8389120):
            logger.info(f'User {user_dn} password expired.', extra={'user': self.user, 'uid': user_dn})
            return True
        else:
            logger.debug(f'User {user_dn} password not expired.', extra={'user': self.user, 'uid': user_dn})
            return False

    def remove_lockout(self, user_dn):
        logger.info(f'Removing lockout from {user_dn}')
        self.set_attribute_value(user_dn, 'lockoutTime', '0')

    def active_lockout(self, user_dn):
        """ Evaluates whether or not a given {user_dn} is locked out of their account. """
        lockout = self.search_base_dn(base_dn=user_dn, attributes=['lockoutTime'], objectClass='user')
        if(lockout[0][1]['lockoutTime'][0].decode('utf-8') != '0' and self.user_status(user_dn) == 514):
            logger.info(f'User {user_dn} locked out.', extra={'user': self.user, 'uid': user_dn})
            return True
        else:
            logger.debug(f'User {user_dn} not locked out.', extra={'user': self.user, 'uid': user_dn})
            return False
