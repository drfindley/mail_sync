#------------------------------------------------------------------------------
# Actions
#------------------------------------------------------------------------------

# If set to True, the script will not invite any new members to Google groups.
# Can also use --skip-invite command line flag.
skip_invite = False

# If set to True, the script will not remove any members from Google groups.
# Can also use --skip-remove command line flag.
skip_remove = False

#------------------------------------------------------------------------------
# Debugging and test flags
#------------------------------------------------------------------------------

# If set to True, prints debugging info.
# Can also use --verbose command line flag.
verbose = False
# If set to True, prints debugging info for browser forms.
# Can also use --debug-forms command line flag.
debug_forms = False

# When set to True, turns off form submissions that actually change data
# on the lists. Coupled with the debug output, this is very useful to test
# the script without having to worry about the data.
# Can use the --make-changes command line flag to turn off this option.
test_mode_only = True

#------------------------------------------------------------------------------
# Authentication
#------------------------------------------------------------------------------

# If these are not specified, the user is prompted interactively.

# lds.org ward web site credentials
# Can also use --lds-username command line option.
lds_username = ""
# Can also use --lds-password command line option.
lds_password = ""

# Google groups credentials
# Can also use --lds-password command line option.
google_username = ''
# Can also use --google-password command line option.
google_password = ''

#------------------------------------------------------------------------------
# Whitelist and blacklist
#------------------------------------------------------------------------------

ward_whitelist = 'spreadsheet:0AgTd0uGWN6wQdFJvbmJPOVZwNEJfWnpmaDBwM2RZRkE'
ward_blacklist = 'spreadsheet:0AgTd0uGWN6wQdFI0OVBPSUU1aEJMeF9xQl9ZaUVBY2c'
ward_leadership = ''

# Note: an address may not appear on both the whitelist and the blacklist.

# These addresses will remain subscribed to Google groups, even though they may
# not be in the membership records.
google_whitelist = set([
    ])

# These addresses will never be subscribed to Google groups, even though they
# may be in the membership records.
google_blacklist = set([
    ])

#------------------------------------------------------------------------------
# Google group names
#------------------------------------------------------------------------------

ward_name = 'Stanford 2nd Ward'
google_ward_list = 'stanford-2nd-ward'
google_leadership_list = 'stanford-2nd-ward-leadership'
google_eq_list = 'stanford-2nd-ward-eq'
google_rs_list = 'stanford-2nd-ward-rs'

#------------------------------------------------------------------------------
# Templates for messages sent to users
#------------------------------------------------------------------------------

# Subject of status report email send to leadership group.
status_report_subject_template = '%(ward_name)s Groups List Maintenance Summary Report'

# Body of status report email send to leadership group.
status_report_body_template = '''This is a status report summarizing maintenance activity on the %(ward_name)s Google Group lists, updated on %(update_time)s.

The following actions were peformed on the mailing lists:

MEMBERS INVITED

Ward List
-----------------------------------------
%(invited_members)s

Elders Quorum List
-----------------------------------------
%(invited_elders)s

Relief Society List
-----------------------------------------
%(invited_sisters)s

MEMBERS REMOVED (Only email addresses are available)

Ward List
-----------------------------------------
%(removed_members)s

Elders Quorum List
-----------------------------------------
%(removed_elders)s

Relief Society List
-----------------------------------------
%(removed_sisters)s

Leadership List
-----------------------------------------
%(removed_leaders)s

MEMBERS WITHOUT EMAIL ADDRESSES

There are %(members_with_no_email_count)d members on LDS.org without an email address.
-----------------------------------------
%(members_with_no_email)s

If you have any questions about these changes, please contact your ward webmasters.

Thank you.'''

# Message added to the top of Google's group join invite message.
invite_template = '''Please accept this invitation to join the %(list_name)s mailing list, used for official announcements and ward business.
        
To do so, simply follow the instructions in the "Google Groups Information" section below.

Thank you.'''

# Message added to the top of Google's group you've been added message
add_template = '''You have been added to the %(list_name)s mailing list, used for official announcements and ward business.

If you do not wish to receive any more emails from this list, please reply to the list administrator.
'''
