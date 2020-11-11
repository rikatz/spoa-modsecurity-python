"""
HAProxy SPOA - Modsecurity and Python
This is a heavily Work in Progress
Run this with the spoa binary, like:
RULES=modsec-rules.conf ./spoa -f modsecurity-spoa.py
"""
import logging
import os
import spoa
import sys
import ModSecurity


class modsectransaction():
    def __init__(self, args):
        # We create a new self.rules so we can add the IgnoreRules here
        self.rules = modsec.rules
        self.modsec = modsec.modsecurity
        for obj in args:
            # TODO: There's for sure a less stupid way of doing this
            if obj['name'] == 'url':
                self.url = obj['value']
                continue
            if obj['name'] == 'method':
                self.method = obj['value']
                continue
            if obj['name'] == 'path':
                self.path = obj['value']
                continue
            if obj['name'] == 'query':
                self.query = obj['value']
                continue
            if obj['name'] == 'reqver':
                self.reqver = obj['value']
                continue
            if obj['name'] == 'ip':
                self.clientip = str(obj['value'])
                continue
            if obj['name'] == 'reqhdrs':
                # TODO: Create a method to convert this to the expected array
                self.reqhdrs = obj['value']
                continue
            if obj['name'] == 'reqbody':
                # TODO: Should this be parsed?
                self.reqbody = obj['value']
                continue
            if obj['name'] == 'ignorerules':
                # TODO: Should this be parsed?
                self.ignorerules = obj['value']
                continue

        # Additional rules per transaction
        if hasattr(self, 'ignorerules') and isinstance(self.ignorerules, str):
            ignorerules = "SecRuleRemoveById " + str(self.ignorerules)
            rules_count = self.rules.load(ignorerules)
            if rules_count < 0:
                msg = 'Error trying to load rules: %s' % self.rules.getParserError()
                logging.warning(msg)
        self.transaction = ModSecurity.Transaction(self.modsec, self.rules)

    def isvalid(self):
        valid = (
            hasattr(self, 'method')
            and hasattr(self, 'path')
            and hasattr(self, 'query')
            and hasattr(self, 'reqver')
            and hasattr(self, 'clientip')
            and hasattr(self, 'reqhdrs')
            and hasattr(self, 'reqbody')
        )
        return valid

    def call_modsec(self):

        # TODO: Can this be configurable? (The SPOE send the information)
        self.transaction.processConnection(self.clientip,
                                           12345,
                                           "127.0.0.1",
                                           11111)
        response = self.process_intervention(self.transaction)
        if response > 0:
            return 1
        path = self.path
        if self.query is not None:
            path = path + "?" + self.query

        self.transaction.processURI(path, self.method, self.reqver)
        response = self.process_intervention(self.transaction)
        if response > 0:
            return 1

        self.parseheaders()
        self.transaction.processRequestHeaders()
        response = self.process_intervention(self.transaction)
        if response > 0:
            return 1

        self.transaction.appendRequestBody(self.reqbody.decode("utf-8"))
        self.transaction.processRequestBody()
        response = self.process_intervention(self.transaction)
        if response > 0:
            return 1

        return 0

    def parseheaders(self):
        '''
        Headers from HAProxy are sent as binaries in the form:
        *(<str:header-name><str:header-value>)<empty string><empty string>
        int:  refer to the SPOE documentation for the encoding
        str:  <int:length><bytes>
        Example:
        4XPTO6ABCDEF
        Ref.: http://cbonte.github.io/haproxy-dconv/2.3/configuration.html#7.3.5-req.hdrs_bin

        The rotine below splits each of Key/Value headers and add to transaction.
        '''

        offset = 0  # In what character are we?

        # Last two characters are disposable (represents the end of the header)
        while offset < len(self.reqhdrs) - 2:
            name_length = int(self.reqhdrs[offset])
            name_end = offset + 1 + name_length
            name = self.reqhdrs[offset+1:name_end]

            value_length = int(self.reqhdrs[name_end])
            value_end = name_end + 1 + value_length
            value = self.reqhdrs[name_end+1:value_end]
            offset = value_end
            self.transaction.addRequestHeader(
                name.decode("utf-8"), value.decode("utf-8"))

    def process_intervention(self, transaction):
        '''
        Check if there's interventions
        : return the apropriate response, if any:
        '''
        intervention = ModSecurity.ModSecurityIntervention()
        if intervention is None:
            return 0

        if transaction.intervention(intervention):
            if intervention.log is not None:
                logging.info(intervention.log)

            if not intervention.disruptive:
                return 0

            # TODO: Deal with response redirection (see the django framework)
            '''
            if intervention.url is not None:
                response = 1
            else:
                response = 0
            '''
            return 1
        else:
            return 0


class ModSec():
    def __init__(self, rules):
        self.logger = logging.getLogger(__name__)
        self.modsecurity = ModSecurity.ModSecurity()
        self.modsecurity.setServerLogCb(self.modsecurity_log_callback)
        self.rules = ModSecurity.Rules()
        self.load_rule_files(rules)

    def modsecurity_log_callback(self, data, msg):
        self.logger.info(msg)

    def load_rule_files(self, rule_file):
        rules_count = self.rules.loadFromUri(rule_file)
        if rules_count < 0:
            msg = '[ModSecurity] Error trying to load rule file %s. %s' % (
                rule_file, self.rules.getParserError())
            self.logger.warning(msg)


def modsecurity(args):
    transaction = modsectransaction(args)
    if transaction.isvalid():
        response = transaction.call_modsec()
    else:
        # TODO: Turn this configurable instead of default denying
        logging.warning("Received an invalid request, denying")
        response = 1

    spoa.set_var_int32("intervention", spoa.scope_sess, response)


logging.basicConfig(level=logging.INFO)
rulefile = os.environ.get('RULES')
global modsec
modsec = ModSec(rules=rulefile)
logging.info("Loaded Modsecurity %s\n", modsec.modsecurity.whoAmI())
spoa.register_message("modsecurity", modsecurity)
