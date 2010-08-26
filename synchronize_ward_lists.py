#!/usr/bin/env python

##
# This script compares the Stanford 2nd Ward membership list from LDS.org to that from the Google Groups
# and synchronizes the membership of the Google Groups lists as much as possible with that of the LDS.org
# lists. In all cases, LDS.org is considered the canonical source.
#
# Behind the scenes, the script uses browser automation to communicate with the LDS.org and Google servers.
# This means that it WILL BREAK if either service changes their web page structures.
#
# When running the script, you will need a login for both the LDS.org and Google Groups sites. Additionally,
# you will need to be an owner or admin on the Google Groups lists in order for this script function properly.
#
# Note: This script requires the Mechanize python library, which acts as the browser and allows the script to
# mimic a real web browser. Find it at: http://wwwsearch.sourceforge.net/mechanize/ .
#
# Written by David "Shoe" Shoemaker (mrshoe at the gmail dot com) and Travis Cripps (tcripps at the gmail dot com).
# Minor improvements by Bruce Christensen (me at the brucec dot net).
# Minor improvements and major gdata awesome by Adam Findley (drfindley at the gmail dot com).
#
# TODO:
#  - Auto-re-invite (for people who haven't accepted their invitations)
#  - Auto add to blacklist (m/f/x/b)
#  - Remove from whitelist when on lds.org
#  - clean up old whitelist/blacklist stuff
#  - change invite message
#  - change invite to add based on config
##

import ClientForm
import config
import csv
import getpass
import mechanize
import optparse
import os
import re
import sys
from time import strftime
from urllib import urlencode
import gdata.docs
import gdata.docs.service
import gdata.spreadsheet.service

#-------------------------------------------------------------------------------

def synchronize_lists():
    validate_config()
    process_command_line()

    if config.test_mode_only:
        print "********************************************************************************"
        print "Note: this is just a dry run; ZERO CHANGES WILL BE MADE to the mailing lists."
        print "To quit dilly-dallying and actually do something, re-run with --make-changes."
        print "********************************************************************************"

    init_browser()

    # Get "master" list from LDS.org.
    lds_members = get_lds_members()
    print "\nGot LDS.org members list with %d members" % len(lds_members)
    whitelist_members = get_list_of_members(config.ward_whitelist)
    print "\nGot %d whitelist members" % len(whitelist_members)

    print "\nMissing emails on lds.org members found on whitelist:"
    for wl_member in whitelist_members:
        wl_member_in_lds_list = False
        for lds_member in lds_members:
            if lds_member.first_name == wl_member.first_name \
              and lds_member.last_name == wl_member.last_name:
                print wl_member
                lds_member.email = wl_member.email
                wl_member_in_lds_list = True
        if not wl_member_in_lds_list:
            lds_members.append(wl_member)

    blacklist_emails = get_list_of_emails(config.ward_blacklist)
    print "\nGot %d blacklist emails" % len(blacklist_emails)
    lds_members = [m for m in lds_members if m.email not in blacklist_emails]

    #Figure out which members from the LDS.org list DO NOT have an email.
    members_with_no_email = [m for m in lds_members if not m.email]
    print "\nMembers with no email address: %d" % len(members_with_no_email)
    if config.verbose:
        print "-------------------------------"
        for member in members_with_no_email:
            print(member)

    members_with_email = [m for m in lds_members if m.email]
    print "\nMembers with email address: %d" % len(members_with_email)
    if config.verbose:
        print "-------------------------------"
        for member in members_with_email:
            print member

    # Get the Google Groups membership for the ward list.
    perform_google_login()
    google_ward_list_members = get_google_members_for_list(config.google_ward_list)
    print "\nMembers from Google %(list_name)s list: %(list_count)d\n-------------------------------" % {
        'list_name': config.google_ward_list,
        'list_count': len(google_ward_list_members)}

    all_lists = [config.google_eq_list,
                 config.google_rs_list,
                 config.google_leadership_list,
                 config.google_ward_list]

    if config.skip_invite:
        print "Skipping sending of invites."
        members_invited_by_list = dict.fromkeys(all_lists)
    else:
        # Determine the members who should be invited to the ward list.
        new_members = set([m
                           for m
                           in members_with_email
                           if m.email not in google_ward_list_members])

        # Now, calculate the membership for the EQ and RS lists.
        # First, we need to identify the gender of the members to invite
        # (while also allowing the user to skip people).
        new_members, new_brothers, new_sisters = segregate(new_members)

        # Invite new members as necessary.
        # Important: changes to the ward list must happen after changes to
        # other lists to avoid inconsistent data if an earlier change fails,
        # since the ward list is the master that the others are based off of.
        invitations = [(config.google_eq_list, new_brothers),
                       (config.google_rs_list, new_sisters),
                       (config.google_ward_list, new_members)]
        members_invited_by_list = send_invites(invitations)
        # Update client-side data structure to reflect changes made to the server.
        google_ward_list_members.update(m.email for m in new_members)

    if config.skip_remove:
        members_removed_by_list = dict.fromkeys(all_lists)
        print "Skipping removal of old members."
    if not config.skip_remove:
        # Remove stale addresses.
        removals = [config.google_eq_list,
                    config.google_rs_list,
                    config.google_leadership_list,
                    config.google_ward_list]
        allowed_addresses = set(member.email for member in members_with_email)
        members_removed_by_list = remove_stale_addresses(removals,
                                                         allowed_addresses,
                                                         {config.google_ward_list: google_ward_list_members})

    # Send a report of the action(s) taken.
    send_summary_action_report(members_invited_by_list, members_removed_by_list, members_with_no_email)

    print "done."

#-------------------------------------------------------------------------------

class Member( object ):
    """Represents a member."""

    def __init__(self, first_name, last_name, email):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email

    def name_lastfirst(self):
        return "%s, %s" % (self.last_name, self.first_name)

    def __repr__(self):
        return "%s <%s>" % (self.name_lastfirst(), self.email)

browser = None # the Browser instance

def init_browser():
    """Sets up the browser instance to look like Safari."""
    global browser
    browser = mechanize.Browser()
    browser.set_handle_robots(False)
    browser.addheaders = [('User-agent', 'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/312.8.1 (KHTML, like Gecko) Safari/312.6')]

email_exp = re.compile(r'^([^<]+)?<(.*)>$') #('[^<]*<([^>]*)>') # email isolation regex
def get_email(name1):
    match = email_exp.match(name1)
    return match and match.groups()[1].strip().lower() or None

first_name_exp = re.compile(r'^([^<]*).*$') # first name isolation regex
def get_first_name(name1):
    match = first_name_exp.match(name1)
    return match and match.groups()[0].strip() or None

last_name_exp = re.compile(r'^([^,]*),.*$') # last name isolation regex
def get_last_name(name1):
    match = last_name_exp.match(name1)
    return match and match.groups()[0].strip() or None

def get_lds_members():
    """Gets the CSV-formatted ward membership list from LDS.org."""

    if config.lds_username is None:
        config.lds_username = raw_input('lds.org username: ').strip()
    if config.lds_password is None:
        config.lds_password = getpass.getpass('Password for %s: ' % config.lds_username)

    login_data = {'vgn_form_encoding': 'UTF8',
                  'nextUrl':'/units/home/0,9781,,00.html',
                  'Submit':'',
                  'URL':'',
                  'username': config.lds_username,
                  'password': config.lds_password}
    print "Retrieving member list from LDS.org...",
    sys.stdout.flush()
    browser.open('https://secure.lds.org/units/a/directory/csv/1,19990,4147-1-7-412031,00.txt', timeout=30)
    r = browser.open('https://secure.lds.org/units/a/login/1,13088,779-1,00.html?URL=', urlencode(login_data), timeout=30)
    print "done."
    return parse_lds_list(r)

def parse_lds_list(csv_list):
    """Parses the LDS.org CSV-formatted membership file."""

    print "Parsing the member records from the LDS.org CSV membership file..."

    dr = csv.DictReader(csv_list)
    members = []

    for row in dr:
        for i in range(1,5): # Get any name records from the 4 name[x] fields, and create a Member from each.
            email_field = 'name%d' % i
            if row[email_field] is not None:
                last_name = get_last_name(row['familyname'])
                first_name = get_first_name(row[email_field])
                email = get_email(row[email_field])
                members.append(Member(first_name, last_name, email))

        if 'name_overflow' in row: #'name_overflow' would hold any name records that overflow the name[1-4] fields.
            for name in row['name_overflow']:
                members.append(Member(get_first_name(name), get_last_name(row['familyname']), get_email(name)))
    return members

def download_list(list_id):
    """ Downloads lists from google docs """
    gd_client = gdata.docs.service.DocsService(source='Stanford2ndWard-GetWhiteLists-v0.1')
    gd_client.ClientLogin(config.google_username,config.google_password)

    entry = gd_client.GetDocumentListEntry('http://docs.google.com/feeds/documents/private/full/' + list_id)
    title = entry.title.text
    
    spreadsheets_client = gdata.spreadsheet.service.SpreadsheetsService()
    spreadsheets_client.ClientLogin(config.google_username,config.google_password)

    docs_auth_token = gd_client.GetClientLoginToken()
    gd_client.SetClientLoginToken(spreadsheets_client.GetClientLoginToken())

    file_path = '%s.csv' % title
    gd_client.Export(entry,file_path)

    gd_client.SetClientLoginToken(docs_auth_token)

    return (file_path, title)

def get_list_of_members(list_id):
    list_file,title = download_list(list_id)
    reader = csv.DictReader(open(list_file))

    members = []
    for row in reader:
        members.append(Member(row['Firstname'],row['Lastname'],row['Email']))
    os.remove(list_file)

    return members

def get_list_of_emails(list_id):
    list_file,title = download_list(list_id)
    reader = csv.DictReader(open(list_file))

    emails = []
    for row in reader:
        emails.append(row['Email'])
    os.remove(list_file)

    return emails

def perform_google_login():
    """Logs into the Google Groups site to start a session for further requests."""

    if not config.google_username:
        config.google_username = raw_input('Google username: ').strip()
    if not config.google_password:
        config.google_password = getpass.getpass('Password for %s: ' % config.google_username)

    browser.open('http://groups.google.com', timeout=30)
    browser.follow_link(text_regex=re.compile('sign in', re.IGNORECASE))
    browser.select_form(nr=0)
    browser['Email'] = config.google_username
    browser['Passwd'] = config.google_password
    browser.submit('signIn')

def open_google_url(url, list_name):
    """Opens a URL with the browser, but looks for an reports HTTP Forbidden responses."""
    r = None
    try:
        r = browser.open(url, timeout=30)
    except mechanize.HTTPError, e:
        http_forbidden = 403
        if http_forbidden == e.getcode():
            print "Error: attempted to open %s" % url
            print "but got a HTTP 403 (forbidden) response."
            print "It's likely that you (%s) do not have admin access to the %s group." % (config.google_username, list_name)
            raise SystemExit(1)
        else:
            raise
    return r

def get_google_members_for_list(list_name):
    """Gets the CSV-formatted membership list from Google Groups for the provided list name."""

    print '\nRetrieving ' + list_name + ' member list from Google Groups...',
    url = 'http://groups.google.com/group/%s/manage_members/%s.csv?Action.Export=Export+member+list' % (list_name, list_name)
    r = open_google_url(url, list_name)
    print "done."
    #print '\n'.join(r.readlines())
    c = csv.reader(r)
    c.next()
    c.next()
    return set(row[0].strip().lower() for row in c)

def invite_members_to_join_list(members, list_name):
    """Invites members to join the Google Groups list for the given list_name."""

    #r = open_google_url('http://groups.google.com/group/%s/members_invite' % list_name, list_name)
    # The below will directly invite people. I think. SCARY!
    r = open_google_url('http://groups.google.com/group/%s/manage_members_add' % list_name, list_name)
    try:
        browser.select_form(name='cr') #'manage_members_add' to add directly
        browser['members_new'] = ', '.join(m.email for m in members)
        message = config.add_template % {'list_name': list_name}
        browser['body'] = message
        # If adding directly, set the email preference: browser['delivery'] = ['1']
        if config.debug_forms: print browser.form
        if not config.test_mode_only:
            browser.submit(name='Action.InitialAddMembers')
    except ClientForm.ControlNotFoundError, error:
        print "ERROR: Could not find a form widget: %s. Time to reexamine the script!" % error

def find_stale_addresses(current_list_members, allowed_members):
    """
    Returns the set of members of a Google group who are no longer in the ward
    (as defined by the lds.org membership list, passed in as allowed_members).
    Whitelisted members are not returned.
    """
    return (current_list_members
            .difference(allowed_members))
            #.difference(config.google_blacklist))
            #.difference(config.google_whitelist))

def remove_members_from_list(member_email_addresses, list_name):
    """Removes the member_email_addresses from the Google Groups list for the given list_name."""
    r = open_google_url('http://groups.google.com/group/%s/manage_members' % list_name, list_name)

    for address in member_email_addresses:
        try:
            # Find the member with the address.
            browser.select_form(name = 'membersearch')
            if config.debug_forms: print browser.form
            browser['member_q'] = address
            r2 = browser.submit()
        except ClientForm.ControlNotFoundError, error:
            print "ERROR: Could not find a form widget: %s. Time to reexamine the script!" % error

        try:
            # Remove the member.
            browser.select_form(name="memberlist")
            browser['membership_type'] = ['unsub']
            browser.form.find_control('subcheckbox').items[0].selected = True
            if config.debug_forms: print browser.form
            if not config.test_mode_only:
                browser.submit(name='Action.SetMembershipType')
        except ClientForm.ControlNotFoundError, error:
            print "ERROR: Could not find a form widget: %s. It's likely that the member was not found, so the widget was not available." % error
            print "\tCould not remove %s from list." % address

def send_summary_action_report(members_invited_by_list,
                               members_removed_by_list,
                               members_with_no_email):
    """Sends a summary report of the maintenance actions to the ward leadership group."""

    invited_members = members_invited_by_list[config.google_ward_list]
    invited_elders = members_invited_by_list[config.google_eq_list]
    invited_sisters = members_invited_by_list[config.google_rs_list]
    removed_members = members_removed_by_list[config.google_ward_list]
    removed_elders = members_removed_by_list[config.google_eq_list]
    removed_sisters = members_removed_by_list[config.google_rs_list]
    removed_leaders = members_removed_by_list[config.google_leadership_list]

    if not (invited_members or invited_elders or invited_sisters or removed_members or removed_elders or removed_sisters or removed_leaders):
        print "\nNo changes were made, so skipping summary report."
        return

    print "Generating summary report..."

    def format_members(members):
        if members:
            return "\n".join(str(m) for m in members)
        return "None"

    message = config.status_report_body_template % {
        'ward_name': config.ward_name,
        'update_time': strftime("%B %d, %Y at %H:%M:%S"),
        'members_with_no_email_count': len(members_with_no_email),
        'members_with_no_email': "\n".join(m.name_lastfirst() for m in members_with_no_email) if members_with_no_email else 'None',
        'invited_members': format_members(invited_members),
        'invited_elders': format_members(invited_elders),
        'invited_sisters': format_members(invited_sisters),
        'removed_members': format_members(removed_members),
        'removed_elders': format_members(removed_elders),
        'removed_sisters': format_members(removed_sisters),
        'removed_leaders': format_members(removed_leaders),
        }

    print "Summary action report (to be sent to leadership list):"
    print "================================================================================"
    print message;
    print "================================================================================"
    confirmation = get_response("Send this report to the leadership list?", ('yes', 'no'), default='yes')

    if confirmation != 'no':
        r = open_google_url('http://groups.google.com/group/%s/post' % config.google_leadership_list, config.google_leadership_list)
        try:
            browser.select_form(name="postform")
            browser['subject'] = config.status_report_subject_template % {'ward_name': config.ward_name}
            browser['body'] = message
            browser.form.find_control('bccme').items[0].selected = True
            if config.debug_forms: print browser.form
            if not config.test_mode_only:
                browser.submit(name='Action.Post')
            print "Report sent."
        except mechanize.FormNotFoundError, error:
            print "ERROR: Could not find form: %s" % error
            print "It's likely that you (%s) do not have admin access to the %s group." % (config.google_username, config.google_leadership_list)
            raise SystemExit(1)
        except ClientForm.ControlNotFoundError, error:
            print "ERROR: Could not find a form widget: %s. Time to reexamine the script!" % error
    else:
        print "Report not sent."

def validate_config():
    dups = config.google_whitelist.intersection(config.google_blacklist)
    if dups:
        print "Error: the following addresses appear on both the whitelist and the blacklist."
        print "Please remove them from one or both:\n -",
        print "\n - ".join(dups)
        raise SystemExit(1)

def process_command_line():
    parser = optparse.OptionParser(usage='usage %prog [options]')
    parser.add_option('--verbose', dest='verbose',
                      default=None, action='store_true',
                      help='prints extra debugging information')
    parser.add_option('--debug-forms', dest='debug_forms',
                      default=None, action='store_true',
                      help='prints form debugging information')
    parser.add_option('--make-changes', dest='test_mode_only',
                      default=None, action='store_false',
                      help='enable form submissions that change data on the lists')
    parser.add_option('--lds-username', dest='lds_username',
                      default=None,
                      help='username for lds.org')
    parser.add_option('--lds-password', dest='lds_password',
                      default=None,
                      help='password for lds.org')
    parser.add_option('--google-username', dest='google_username',
                      default=None,
                      help='password for Google groups admin account')
    parser.add_option('--google-password', dest='google_password',
                      default=None,
                      help='password for Google groups admin account')
    parser.add_option('--skip-invite', dest='skip_invite',
                      default=None, action='store_true',
                      help='skips inviting new members to Google groups')
    parser.add_option('--skip-remove', dest='skip_remove',
                      default=None, action='store_true',
                      help='skips removal of members from Google groups')

    options, args = parser.parse_args()
    if args:
        parser.print_help()
        raise SystemExit(1)

    options_to_copy = ['lds_username',
                       'lds_password',
                       'google_username',
                       'google_password',
                       'verbose',
                       'test_mode_only',
                       'debug_forms',
                       'skip_invite',
                       'skip_remove']
    for option in options_to_copy:
        value = getattr(options, option)
        if value is not None:
            setattr(config, option, value)

def get_response(prompt, choices, default=None):
    """
    Prompts the user to enter a response, and continues to do so until the
    response is one of the valid choices.
    """
    choice_string = ' (%s)' % '/'.join(choices)
    if default is not None:
        choice_string += ' [%s]' % default
    choice_string += ': '
    response = None
    while not response in choices:
        response = raw_input(prompt + choice_string).strip().lower()
        if response == '' and default is not None:
            response = default
    return response

def segregate(potential_new_members):
    """
    Asks the user to identify gender of new members, while also providing the
    option to not invite the person to any lists.
    """
    new_members = set()
    new_brothers = set()
    new_sisters = set()
    # Prompt for the gender of each member.
    for member in sorted(potential_new_members):
        if member.email in config.google_blacklist:
            continue
        gender = get_response('Is %s male or female? (or x to skip)' % member, ('m', 'f', 'x'))

        if gender == 'm':
            new_brothers.add(member)
        elif gender == 'f':
            new_sisters.add(member)

        if gender == 'x':
            print "Skipping member: %s. Will not invite to mailing lists.\n" % member
        else:
            new_members.add(member)
    print

    return new_members, new_brothers, new_sisters

def send_invites(invitations):
    """
    Invites new people to a list.
    """
    members_invited_by_list = {}
    for list_name, members_to_invite in invitations:
        members_invited_by_list.setdefault(list_name, set())
        if members_to_invite:
            output = "Members to invite to %s:" % list_name
            print output
            print "-" * len(output)
            print '\n'.join(sorted(m.email for m in members_to_invite))
            print
            confirmation = get_response('Invite these members?', ('yes', 'no'), default='yes')
            if confirmation == 'yes':
                invite_members_to_join_list(members_to_invite, list_name)
                members_invited_by_list[list_name] = members_to_invite
                print "Invited %d members to %s." % (len(members_to_invite), list_name)
            else:
                print "Did not invite any members to %s." % list_name
        else:
            print "No new members to invite to %s" % list_name
        print

    return members_invited_by_list

def remove_stale_addresses(lists_to_clean, allowed_addresses, list_membership_cache):
    """
    Removes addresses not in allowed_addresses from all lists in lists_to_clean.
    list_membership_cache maps is used for optimization, and maps from a list
    name to a set of the list's members.
    """
    members_removed_by_list = {}
    for list_name in lists_to_clean:
        google_list_members = list_membership_cache.get(list_name)
        if not google_list_members:
            google_list_members = get_google_members_for_list(list_name)
        members_to_remove = find_stale_addresses(google_list_members, allowed_addresses)
        members_removed_by_list.setdefault(list_name, set())
        if members_to_remove:
            output = "Members to remove from %s:" % list_name
            print output
            print "-" * len(output)
            print '\n'.join(sorted(members_to_remove))
            print
            confirmation = get_response('Remove these members?', ('yes', 'no'), default='yes')
            if confirmation == 'yes':
                remove_members_from_list(members_to_remove, list_name)
                members_removed_by_list[list_name] = members_to_remove
                print "Removed %d members from %s." % (len(members_to_remove), list_name)
            else:
                print "Did not remove any members from %s." % list_name
        else:
            print "No members to remove from %s" %  list_name
        print

    return members_removed_by_list

if __name__ == '__main__':
    synchronize_lists()
