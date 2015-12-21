# sensu-plugins

TBD: convert code according to new sensu plugins guidelines & conventions

## check-security.rb

Perform various security checks and raise warnings:
- if there are users with UID=0 or GID=0 except root;
- if there are groups with GID=0 except root;
- if there are members of groups with GID=0;
- if such users can login with or without password;
- if such users can login with SSH by key authentication;
- if there is something in /etc/sudoers and /etc/sudoers.d/* not explicitly allowed (see sudoers.allowed file).

### Requirements

- sudo >= 1.8.9 (because of visudo `-x` flag);
- hashdiff gem.

### Using

- place check-security.rb to /etc/sensu/plugins/ and sudoers.allowed to /etc/sensu/conf.d/ on client nodes;
- make the plugin executable: `chmod +x /etc/sensu/plugins/check-security.rb`;
- add `sensu ALL = NOPASSWD: /etc/sensu/plugins/check-security.rb` to your sudoers;
- invoke it with sudo: `"command": "sudo /etc/sensu/plugins/check-security.rb -a /etc/sensu/conf.d/sudoers.allowed"`.
