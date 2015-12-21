#!/usr/bin/env ruby

require 'sensu-plugin/check/cli'
require 'etc'
require 'json'
require 'hashdiff'
require 'yaml'

class CheckSecurity < Sensu::Plugin::Check::CLI

  option :allowed,
         short: '-a PATH',
         long: '--allowed PATH',
         required: true,
         description: 'Path to a sudoers.allowed file'

  # http://stufftohelpyouout.blogspot.ru/2013/11/recursively-sort-arrays-and-hashes-by.html
  def recursively_sort_arrays_and_hashes!(obj)
    case obj
    when Array
      obj.map! { |v| recursively_sort_arrays_and_hashes!(v) }.sort_by! { |v| (v.to_s rescue nil) }
    when Hash
      obj = Hash[Hash[obj.map { |k, v| [recursively_sort_arrays_and_hashes!(k), recursively_sort_arrays_and_hashes!(v)] }].sort_by { |k, v| [(k.to_s rescue nil), (v.to_s rescue nil)] }]
    else
      obj
    end
  end

  def run
    users_with_uid_or_gid_0 = []
    groups_with_gid_0 = []
    users_in_groups_with_gid_0 = []
    able_to_login_users = []
    able_to_ssh_users = []

    # Get users whose UID or GID is 0
    Etc.passwd { |u| users_with_uid_or_gid_0 << u.name if u.uid == 0 || u.gid == 0 }

    # Get groups whose GID is 0
    Etc.group { |g| groups_with_gid_0 << g.name if g.gid == 0 }

    # Get members of groups whose GID is 0
    groups_with_gid_0.each { |g| users_in_groups_with_gid_0 << Etc.getgrnam(g).mem }
    users_in_groups_with_gid_0.flatten!

    dangerous_users = (users_with_uid_or_gid_0 + users_in_groups_with_gid_0).uniq

    # Check those who can login with or without password
    dangerous_users.each do |u|
      name, status = `passwd -S #{u}`.strip.split
      able_to_login_users << name unless status == "L"
    end

    # Check those who can authorize by SSH
    dangerous_users.each do |u|
      able_to_ssh_users << u if File.exists?(Etc.getpwnam(u).dir + "/.ssh/authorized_keys")
    end

    # root UID and GID are 0 so don't count it
    users_with_uid_or_gid_0.delete("root")
    groups_with_gid_0.delete("root")

    # Load sudoers
    allowed = JSON.load(`visudo -f #{config[:allowed]} -x -`)
    this_node = JSON.load(`visudo -x -`)

    # Sort objects before comparing
    recursively_sort_arrays_and_hashes!(allowed)
    recursively_sort_arrays_and_hashes!(this_node)

    diff = HashDiff.diff(allowed, this_node)

    if users_with_uid_or_gid_0.empty? && groups_with_gid_0.empty? && users_in_groups_with_gid_0.empty? && able_to_login_users.empty? && able_to_ssh_users.empty? && !diff.map { |o, k, v| o }.include?("+")
      ok
    else
      output = ["\n"]
      output << "Users [" + users_with_uid_or_gid_0.join(", ") + "] UID or GID is 0" unless users_with_uid_or_gid_0.empty?
      output << "Groups [" + groups_with_gid_0.join(", ") + "] GID is 0" unless groups_with_gid_0.empty?
      output << "Users [" + users_in_groups_with_gid_0.join(", ") + "] are members of group whose GID is 0" unless users_in_groups_with_gid_0.empty?
      output << "Users [" + able_to_login_users.join(", ") + "] can login with or without password" unless able_to_login_users.empty?
      output << "Users [" + able_to_ssh_users.join(", ") + "] can authorize by SSH" unless able_to_ssh_users.empty?

      # Format to YAML for better (comparing to JSON) readability
      diff.each { |o, k, v| output << "sudo - #{k}:" << v.to_yaml if o == "+" }
      warning output.join("\n")
    end
  end
end
