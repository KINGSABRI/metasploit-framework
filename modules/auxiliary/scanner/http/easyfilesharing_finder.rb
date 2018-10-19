class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'File Sharing Web Server Finder',
      'Description'    => %q{
        This module finds File Sharing Web Servers and list available relevant CVE's or exploit-db(EDB) number to the found versions.
      },
      'Author'         => [ 'Sabri Hassanyah (@KINGSABRI) <King.Sabri[at]gmail.com>' ],
      'License'        => MSF_LICENSE,
      'References'  =>
        [
          ['EDB', '39008'],
          ['PACKETSTORM', '143382']
        ],
    ))

    register_options([
      OptString.new('TARGETURI', [ true, 'The URI to use', '/']),
      OptEnum.new('HTTP_METHOD', [ true, 'HTTP Method to use, HEAD or GET', 'HEAD', ['GET', 'HEAD'] ])
    ])
  end

  def cve(version)
    ref = {
      1 => ['EDB-23222', 'EDB-30856'],
      2 => ['EDB-30856'],
      3 => ['CVE-2006-1161', 'EDB-30856', ],
      4 => ['EDB-30856'],
      5 => ['EDB-30856'],
      6 => ['CVE-2018-9059', 'CVE-2014-5178', 'CVE-2014-3791', 'CVE-2014-9439'],
      7 => ['CVE-2018-9059', 'CVE-2014-5178', 'CVE-2014-3791', 'CVE-2014-9439']
    }
    ref[version]
  end

  def server_response
    uri = normalize_uri(target_uri.path)
    method = datastore['HTTP_METHOD']
    vprint_status("#{peer}: requesting #{uri} via #{method}")

    res = send_request_cgi({
      'uri'     => uri,
      'method'  => method
    })

    unless res
      vprint_error("#{peer}: connection timed out")
      return
    end

    headers = res.headers
    unless headers
      vprint_status("#{peer}: no headers returned")
      return
    end

    return headers
  end


  def run_host(ip)
    return if server_response.nil?
    header  = server_response['Server']
    version = version = header.match(/\d+/).to_s.to_i

    if header.match? /Easy File Sharing Web Server.*/
      print_good "#{peer}: #{header}"
      print_good "Related CVEs and EDBs:"
      cve(version).each {|ref| print_good("    - #{ref}") unless ref.nil?}
    else
      print_warning "Naah"
    end
  end

end
