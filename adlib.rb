
# library for dealing with Active Directory

require 'yaml'

def get_config
  conf_file = "ad-tools.yaml"
  begin
    config = YAML.load_file(conf_file)
  rescue Errno::ENOENT
    abort "Missing #{conf_file}!"
  end
  if config[:passprog] == true
    config[:pass] = `#{config[:adminpass]}`
  end
  return config
end

config = get_config

BINDUSER = config[:binduser]
BINDPASS = config[:bindpass]
ADMINUSER = config[:user]
ADMINPASS = config[:pass]

# Class for all Active Directory methods
class AD

  # Finds the next unix uidnumber available in AD
  def find_next_uid(domain)
    ldap = ldap_connect(domain)
    filter = Net::LDAP::Filter.eq("msSFU30MaxUidNumber", "*")
    treebase = domain.gsub(/\./, ',dc=')
    treebase = treebase.insert(0, 'dc=')
    attrs = [ "msSFU30MaxUidNumber" ]
    results = ldap.search(:base => treebase, :filter => filter, :attrinbutes => attrs)
    results.each do |entry|
      lastUidNumber = entry.mssfu30maxuidnumber[0].to_i
      nextUidNumber = lastUidNumber.to_s
      return nextUidNumber
    end
  end

  # Connect to AD server
  def ldap_connect(domain,binddn=BINDUSER,bindpw=BINDPASS)
    binddn = binddn + "@" + domain
    ldap = Net::LDAP.new(:host => domain,
                         :port => 389,
                         :auth => {
                           :method => :simple,
                           :username => binddn,
                           :password => bindpw,
                         })
    return ldap
  end

  # Pull a user account
  def get_account(domain,samaccountname,attrs = [])
    ldap = ldap_connect(domain)
    treebase = domain.gsub(/\./, ',dc=')
    treebase = treebase.insert(0, 'dc=')
    filter = Net::LDAP::Filter.eq("samaccountname", samaccountname)
    attrs = [ "dn", "cn", "samaccountname", "mail" ] if attrs.length == 0
    results = ldap.search(:base => treebase, :filter => filter, :attributes => attrs)
    if results.length == 0
      return nil
    else
      results.each do |entry|
        return entry
      end
    end
  end

  # Testing! Returns chained groups (groups within groups)
  def get_object_chained(domain,samaccountname,attrs = [])
    ldap = ldap_connect(domain)
    treebase = domain.gsub(/\./, ',dc=')
    treebase = treebase.insert(0, 'dc=')
    filter = Net::LDAP::Filter.eq('samaccountname', samaccountname)
    attrs = [ 'dn', 'samaccountname', 'member' ]
    group = ldap.search(:base => treebase, :filter => filter, :attributes => attrs).first
    if group.nil?
      return nil
    end
    property = group.dn.gsub(/(CN=.*,)/, '\1')
    filter1 = Net::LDAP::Filter.eq('objectclass', 'user')
    filter2 = Net::LDAP::Filter.construct("memberof:1.2.840.113556.1.4.1941:=#{group.dn}")
    filter = Net::LDAP::Filter.join(filter1, filter2)
    attrs = [ 'dn', 'samaccountname' ]
    results = ldap.search(:base => treebase, :filter => filter, :attributes => attrs)
    chained_group = {}
    chained_group[:samaccountname] = group.samaccountname
    chained_group[:dn] = group.dn
    chained_group[:members] = results
#    chained_group[:orig_members] = group.member
#    if chained_group.length <= 0
#      return nil
#    else
      return chained_group
#    end
  end

  # get info from specific dn
  def get_dn(domain,dn,return_attrs = [])
    scope = Net::LDAP::SearchScope_BaseObject
    ldap = ldap_connect(domain)
    results = ldap.search(:base => dn, :scope => scope, :attributes => return_attrs)
    if (results.nil? || results.length == 0)
      return nil
    else
      results.each do |entry|
        return entry
      end
    end
  end

  # A more generic version of AD.get_account
  def get_entry(domain,search_key,search_value,return_attrs = [])
    @domain = domain
    @search_key = search_key
    @search_value = search_value
    @return_attrs = return_attrs
    @treebase = @domain.gsub(/\./, ',dc=')
    @treebase = @treebase.insert(0, 'dc=')
    ldap = ldap_connect(@domain)
    filter = Net::LDAP::Filter.eq(@search_key,@search_value)
    results = ldap.search(:base => @treebase, :filter => filter, :attributes => @return_attrs)
    if (results.nil? || results.length == 0)
      return nil
    else
      results.each do |entry|
        return entry
      end
    end
  end

  # Add unix attributes to account
  def add_unix_attributes(domain,entry,ua)
    ldap = ldap_connect(domain,ADMINUSER,ADMINPASS)
    print "Adding attributes..."
    ua.each do |at, va|
      ldap.add_attribute entry[:dn][0], at, va
    end
    increment_maxuid(ldap,domain)
    puts ""
    print "Done!\n"
  end

  # Generate unix attributes hash
  def gen_unix_attributes(ad,domain,entry)
    ua = Hash.new
    ua[:uidnumber] = ad.find_next_uid(domain)
    ua[:mssfu30name] = entry[:samaccountname][0]
    ua[:mssfu30nisdomain] = domain.split(".").first
    ua[:gidnumber] = "100"
    ua[:unixhomedirectory] = "/home/" + entry[:samaccountname][0]
    ua[:loginshell] = "/bin/bash"
    return ua
  end

  # Increment maxuid on AD server, which must be manually done
  def increment_maxuid(ldap,domain)
    treebase = domain.gsub(/\./, ',dc=')
    treebase = treebase.insert(0, 'dc=')
    attrs = [ "msSFU30MaxUidNumber" ]
    filter = Net::LDAP::Filter.eq("msSFU30MaxUidNumber", "*")
    results = ldap.search(:base => treebase, :filter => filter, :attrinbutes => attrs)
    results.each do |entry|
      newmaxuid = entry.mssfu30maxuidnumber[0].to_i+ 1
      newmaxuid = newmaxuid.to_s
      ldap.replace_attribute entry[:dn][0], :mssfu30maxuidnumber, newmaxuid
    end
  end

  # Add Attributes to existing entry. value should be full DN
  # use domain, dn of object to modify, attribute to add, value of that attr
  def update_object(method,domain,object,attribute,value)
    @ldap = ldap_connect(domain,ADMINUSER,ADMINPASS)
    begin
      if (method == 'add')
        @ldap.add_attribute(object,attribute,value)
      elsif (method == 'replace')
        @ldap.replace_attribute(object.to_s,attribute,value)
      end
    rescue Exception => e
      puts
      puts "  Error: #{e.message}"
      puts "  Error: #{e.backtrace.inspect}"
      puts "  Error: #{@ldap.get_operation_result.error_message}"
      puts "  Error: #{@ldap.get_operation_result.code}: #{@ldap.get_operation_result.message}"
      puts
      abort
    else
      puts "  Result: #{@ldap.get_operation_result.code}: #{@ldap.get_operation_result.message}"
    end
  end

  def find_domain(short_domain)
    case short_domain
    when "ad1"
      domain = "ad1.example.com"
    when "ad2"
      domain = "ad2.example.com"
    else
      domain = nil
    end
  end

  # Mark these method as private
  private :ldap_connect
  private :find_domain
end
