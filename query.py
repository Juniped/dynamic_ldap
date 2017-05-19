#!/usr/bin/python
import ldap
import ldap.sasl
import sys
import getpass  # NOQA
import ldap  # NOQA
import ldap.sasl  # NOQA
import datetime  # NOQA
import csv  # NOQA
import datetime  # NOQA
from operator import itemgetter  # NOQA

USERNAME = getpass.getuser()
LDAP_URI = "ldap://ldap.corp.redhat.com"

all_fields = ["dn","uid","cn","homeDirectory","givenName","manager","telephoneNumber","title","uidNumber","rhatLocation","rhatCostCenter","rhatHireDate","rhatPersonType","rhatTermDate","rhatGeo","rhatCostCenterDesc","rhatNickName","ntUserdomainId","mobile","sn","memberOf","mail","rhatOfficeFloor",]


class LdapQuery:
    def __init__(self, login="anonymous", pw=""):
        '''Initialize LDAP.'''
        try:
            auth = ldap.sasl.gssapi("")
            self.ldap_connection = ldap.initialize(LDAP_URI)
            self.ldap_connection.simple_bind_s("", "")
            # print ldap.OPT_X_TLS_CACERTFILE
            # ldap.set_option(ldap.OPT_X_TLS_CACERTFILE,
            #     '/etc/openldap/certs/cacert.crt')
            #     # '/etc/openldap/certs/newca.crt')
            # # ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)

            # if login == "anonymous":
            #     self.ldap_connection.simple_bind_s("", "")
            # else:
            #     self.ldap_connection.start_tls_s()
            #     # Authenticate with your kerberos ticket
            #     self.ldap_connection.sasl_interactive_bind_s("",auth)
        except ldap.LDAPError, e:
            sys.stderr.write("Fatal LDAP Error.\n")
            sys.stderr.write("Error: %s\n" % e)
            print "\nExiting."
            raise SystemExit(1)
            # this WILL cause the script to fail if not on trusted
            # recommend raise a network error exception which will
            # also provide a stack trace, showing failure within
            # the LDAP class

    def locate_user_by(self, search_type, search_var, fields="all"):
        ldap_filter = ""
        if search_type == "manager":
            ldap_filter = "manager=uid={0}".format(search_var)
        else:
             ldap_filter = "{}={}".format(search_type, search_var)

        return_fields = all_fields

        return self.ldap_connection.search_s("ou=Users,dc=redhat,dc=com",
            ldap.SCOPE_SUBTREE, ldap_filter, return_fields)

    def locate_group_users(self, group):
        """"Return a dictionary of users in specified group."""
        return self.ldap_connection.search_s("ou=Groups,dc=redhat,dc=com",
            ldap.SCOPE_SUBTREE, 'cn={0}'.format(group))

    def locate_user(self, user):
        """Return a dictionary with the user's info."""
        return self.ldap_connection.search_s("dc=redhat,dc=com",
            ldap.SCOPE_SUBTREE, "uid={0}".format(user), all_fields)

    def locate_all_users(self, fields="all"):
        """Return a dictionary with the user's info."""
        if fields == "all":
            return_fields = all_fields
        else:
            return_fields = fields
        return self.ldap_connection.search_s("ou=Users,dc=redhat,dc=com",
            ldap.SCOPE_SUBTREE, "uid=*", return_fields)

    def locate_users_by_geo(self, geo):
        return self.ldap_connection.search_s("ou=Users,dc=redhat,dc=com",
            ldap.SCOPE_SUBTREE, "rhatGeo={0}".format(geo), all_fields)

    def locate_users_with_gapps(self):
        """Returns a list of UID(s) using Google mail"""
        return self.ldap_connection.search_s("ou=mx,dc=redhat,dc=com",
            ldap.SCOPE_SUBTREE, "(|(sendmailMTAAliasValue=*@gapps.redhat.com)(sendmailMTAKey=*@gapps.redhat.com))",
            ["sendmailMTAKey", "sendmailMTAAliasValue", "rhatMTAAllowExternal"])

    def locate_users_with_zimbra(self):
        '''Returns a list of UID(s) using Zimbra mail'''
        return self.ldap_connection.search_s("ou=mx,dc=redhat,dc=com", ldap.SCOPE_SUBTREE,
            "(|(sendmailMTAAliasValue=*@mail.corp.redhat.com)(sendmailMTAKey=*@mail.corp.redhat.com))",
            ["sendmailMTAKey", "sendmailMTAAliasValue", "rhatMTAAllowExternal"])

    def locate_users_by_manager(self, user, fields=all_fields):
        """Returns a list of uid based on the 'manager' field."""
        return self.ldap_connection.search_s("ou=Users,dc=redhat,dc=com",
            ldap.SCOPE_SUBTREE, "manager=uid=" + user +
            ",ou=Users,dc=redhat,dc=com", fields)

    def locate_users_by_hiredate(self, querydate):
        """Returns a list of UID's based on a specific hire date"""
        return self.ldap_connection.search_s("ou=Users,dc=redhat,dc=com",
            ldap.SCOPE_SUBTREE, "rhatHireDate=" + querydate +
            ",ou=Users,dc=redhat,dc=com", ["uid", "cn", "rhatHireDate"])

    def locate_users_by_position(self, title):
        """Returns a list of UID's with specific criteria in their title"""
        return self.ldap_connection.search_s("ou=Users,dc=redhat,dc=com",
            ldap.SCOPE_SUBTREE, "title=*{0}*".format(title), all_fields)

    def locate_new_accounts(self, querydate):
        """Query LDAP for accounts created after the querydate"""
        return self.ldap_connection.search_s("ou=Users,dc=redhat,dc=com",
            ldap.SCOPE_SUBTREE, "rhatHireDate>=" + querydate +
            ",ou=Users,dc=redhat,dc=com", ["uid", "cn", "rhatHireDate",
            "rhatCostCenter", "manager"])

    def manager_info(self, manager_cn):
        """Return manager's name and login, based on ldap search."""
        manager_login = manager_cn[4:manager_cn.find(",")]
        manager_info = self.locate_user(manager_login)
        try:
            return manager_info[0][1]['cn'][0] + \
            " (" + manager_info[0][1]['uid'][0] + ")"
        except IndexError:
            return "(LDAP record removed) %s" % manager_cn

    def locate_user_by_cost_center(self, cost_center):
        pass

    def get_deleted_users(self):
        """returns a list of deleted users"""
        return self.ldap_connection.search_s("ou=DeletedUsers,dc=redhat,dc=com",
            ldap.SCOPE_SUBTREE, "uid=*", ["uid"])

    def pull_rhds_group(self, name):
        """Returns a RHDS Group"""
        return self.ldap_connection.search_s("ou=managedGroups,dc=redhat,dc=com",
            ldap.SCOPE_SUBTREE,"cn={0}".format(name))

    def pull_all_rhds_group(self):
        """Returns a RHDS Group"""
        return self.ldap_connection.search_s("ou=managedGroups,dc=redhat,dc=com",
            ldap.SCOPE_SUBTREE)

    def find_alias(self, alias):
        return self.ldap_connection.search_s("ou=mx,dc=redhat,dc=com",
            ldap.SCOPE_SUBTREE, "sendmailMTAKey={}".format(alias))

    def ldap_disconnect(self):
        """Disconnect from LDAP."""
        try:
            self.ldap_connection.unbind()
        except ldap.LDAPError, e:
            print e
            pass

myquery = LdapQuery(login=USERNAME)
all_fields.sort()

print "Current Searchable  LDAP Fields:"
print all_fields
print "------------------------------------\n"
search_type = raw_input('Input LDAP search field: ')
search_var = raw_input('Input search variable (ex. [*, pcarlson]): ')

result = myquery.locate_user_by(search_type,search_var)
field_list = ', '.join(all_fields)
with open("query_results.csv","w") as f:
    f.write(field_list + "\n")
    # with op
    for user in result:
        row_string = ''
        for x in range(len(all_fields)):
            try:
                row_string = ''.join((row_string, user[1][all_fields[x]][0], ", "))
            except KeyError:
                row_string = ''.join((row_string, "N/A", ", "))
        # f.write(user[1]
        f.write(row_string + "\n")

print "Results written to query_results.csv"
