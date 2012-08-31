require 'rubygems'
require 'sinatra'
require 'rack/utils'
require 'uri'
require 'json'
require 'uuid'
require 'net/http'
require 'net/https'
require 'singleton'
require 'sequel'
require 'pp'
require 'date'
require 'time'
# require 'RMagick'
require 'mini_magick'
require './setup.rb'

ABOUT_MSG = <<-EOM
<p>PlainSquare is a lightweight Foursquare client for mobile web browsers. It is intended as a full-featured substitute for Foursquare Mobile. PlainSquare supports both geolocation (using device GPS or cellular / wi-fi positioning) and manual coordinate entry for phones without GPS.

<p>PlainSquare speeds up check-ins by making this operation single-click if you do not need to shout or change your broadcast options. PlainSquare is also designed to send you through as few screens as possible to do most common Foursquare tasks.

<p>PlainSquare uses OAuth version 2 to log in to Foursquare to avoid having to store user passwords. PlainSquare supports version 2 of the Foursquare API. It is written in Ruby and designed for hosting on Heroku or OpenShift.

<pre>
Version: 0.0.4
Author: Po Shan Cheah (<a href="mailto:morton@mortonfox.com">morton@mortonfox.com</a>)
Source code: <a href="http://code.google.com/p/plainsq/">http://code.google.com/p/plainsq/</a>
Created: November 21, 2011
Last updated: August 30, 2012
</pre>
EOM

USER_AGENT = 'plainsq_qslw:0.0.4 20120830'
TOKEN_COOKIE = 'plainsq_token'

AUTH_URL = 'https://foursquare.com/oauth2/authenticate'
ACCESS_URL = 'https://foursquare.com/oauth2/access_token'
API_URL = 'https://api.foursquare.com/v2'

DEFAULT_LAT = '39.7'
DEFAULT_LON = '-75.6'
DEBUG_COOKIE = 'plainsq_debug'

METERS_PER_MILE = 1609.344

# Send location parameters if distance is below MAX_MILES_LOC.
MAX_MILES_LOC = 1.1

if $DATABASE_URL =~ /sqlite/
  # In development environment, use local callback.
  # Also need to use a different consumer because Foursquare
  # checks the callback URL.
  CALLBACK_URL = 'http://localhost:5000/oauth'
  CLIENT_ID = 'SR4KMLAZA1OJUCI4DN3PEFSSN024B3TXKDHYYG5QOFBQVBRD'
  CLIENT_SECRET = 'U5ULMVFC5N1QPAPBPQLAN0MI3BWREMBCJLGYOR3KT15AMTQJ'
else
  # Production environment.
  CALLBACK_URL = 'http://www.qslw.com/oauth'
  CLIENT_ID = 'IUWZ0RTGVGJF1QL3KNGMM3SHMNWTWNDIU2NNU422E30QR1DD'
  CLIENT_SECRET = 'KIM2K03UADKK0YWXVMFIZ2DBXOCJJF00QLVQ20XLJ2AZEROD'
end


class Response
  def initialize status = 200
    @resp = Sinatra::Response.new([], status)
    @resp['User-Agent'] = USER_AGENT
  end

  def error errcode = 503
    initialize errcode
  end

  def puts str
    @resp.write(str + "\n")
  end

  def resp
    @resp.finish
  end

  def errorpage msg, errcode = 503
    error errcode
    htmlbegin 'Error'
    puts "<p><span class=\"error\">Error: #{msg}</span>"
    htmlend
  end

  def htmlbegin title, params = {}
    nolocate = params[:nolocate] || false
    puts <<-EOM
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>PlainSq - #{title}</title>

<meta name="HandheldFriendly" content="true" />
<meta name="viewport" content="width=device-width, height=device-height, user-scalable=yes" />

<link rel="stylesheet" href="/main.css" type="text/css" />
<link rel="stylesheet" href="/mobile.css" type="text/css" media="handheld, only screen and (max-device-width:480px)" />

<script type="text/javascript">
// Fix for Android 2.2 CSS media type problem.
// From: http://www.paykin.info/java/android-css-media-reloading/
var isandroid = /android/.test(navigator.userAgent.toLowerCase());
if (isandroid) {
    var cssLink = document.createElement("link");
    cssLink.setAttribute("type", "text/css");
    cssLink.setAttribute("rel", "stylesheet");
    cssLink.setAttribute("href", "/mobile.css");
    document.head.appendChild(cssLink);
}
</script>
</head>

<body>
<div class="header"><a class="button" href="/">Home</a>#{nolocate ? '' : '<span class="beforesep"><a class="button" href="/geoloc">Locate</a></span>'} - #{title}</div>
    EOM
  end

  def htmlend params = {}
    noabout = params[:noabout] || false
    nologout = params[:nologout] || false
    puts <<-EOM
<div class="footer"><a class="button" href="/">Home</a>#{noabout ? '' : '<span class="beforesep"><a class="button" href="/about">About</a></span>'}#{nologout ? '' : '<span class="beforesep"><a class="button" href="/logout">Log out</a></span>'}</div>
</body>
</html>
    EOM
  end

  def no_cache
    # Turn off web caching so that the browser will refetch the page.
    @resp['Cache-Control'] = 'no-cache'
  end

  def del_cookie cookie
    @resp.delete_cookie cookie
  end

  def set_cookie cookie, value
    # Expiration date is 20 years from now.
    @resp.set_cookie cookie, { :value => value, :expires => (Time.now + 20 * 365 * 24 * 60 * 60) }
  end

  def redirect target
    @resp.redirect target
  end
  
  # Set the debug option cookie.
  def set_debug debug
    # No expiration. Debug cookie should not be saved to disk.
    @resp.set_cookie DEBUG_COOKIE, debug ? 1 : 0
  end
end

def uri_encode_form params
  params.map { |k, v|
    "#{k}=#{escapeURI v}"
  }.join '&'
end

# OAuth 2.0 client.
class Client
  POST = 'POST'
  GET = 'GET'

  def initialize client_id, client_secret, callback_url, auth_url, access_url, api_url
    @client_id = client_id
    @client_secret = client_secret
    @callback_url = callback_url
    @auth_url = auth_url
    @access_url = access_url
    @api_url = api_url
  end

  # Return authentication URL to which users must be redirected to do an
  # OAuth login.
  def requestAuth
    uri = URI @auth_url
    uri.query = uri_encode_form({
      :client_id => @client_id,
      :response_type => 'code',
      :redirect_uri => @callback_url
    })
    uri
  end

  def accessToken= tok
    @accessToken = tok
  end

  def accessToken
    @accessToken
  end

  # Swap an authentication code for an access token.
  def requestSession auth_code
    uri = URI @access_url
    uri.query = uri_encode_form({
      :client_id => @client_id,
      :client_secret => @client_secret,
      :redirect_uri => @callback_url,
      :grant_type => 'authorization_code',
      :code => auth_code
    })

    http = Net::HTTP.new uri.host, uri.port
    http.use_ssl = true
    if RUBY_PLATFORM == 'i386-mingw32'
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end
    res = http.start { |http|
      http.request Net::HTTP::Get.new uri.request_uri
    }
    case res
    when Net::HTTPSuccess
      jsn = JSON.parse res.body
      @accessToken = jsn['access_token']
      jsn
    else
      raise "Error from #{uri}: #{res.code} #{res.message}"
    end
  end

  # Generate multipart/form-data headers and data for uploading photos. The
  # photo must have the key 'photo' to be recognized as such.
  def multipart_encode params
    boundary = UUID.generate :compact
    content_type = "multipart/form-data; boundary=#{boundary}"
    data = ''
    params.each { |k, v|
      data += "--#{boundary}\r\n"
      if k == :photo
        data += "Content-Disposition: form-data; name=\"#{k}\"; filename=\"#{k}.jpg\"\r\n"
        data += "Content-Type: image/jpeg\r\n"
      else
        data += "Content-Disposition: form-data; name=\"#{k}\"\r\n"
      end
      data += "\r\n#{v}\r\n"
    }
    data += "--#{boundary}--\r\n\r\n" 
    [ data, content_type ]
  end

  # Perform an API call with the access token. If params has a 'photo' key,
  # do a multipart form-data upload.
  def makeRequest method, path, params = {}
    params[:oauth_token] = @accessToken

    uri = nil
    req = nil

    if params[:photo]
      data, content_type = multipart_encode params
      uri = URI "#{@api_url}/#{path}"

      req = Net::HTTP::Post.new uri.path
      req.body = data
      req.content_type = content_type
    elsif method == POST
      uri = URI "#{@api_url}/#{path}"

      req = Net::HTTP::Post.new uri.path
      req.set_form_data params
    else
      uri = URI "#{@api_url}/#{path}"
      uri.query = uri_encode_form params

      req = Net::HTTP::Get.new uri.request_uri
    end

    http = Net::HTTP.new uri.host, uri.port
    http.use_ssl = true
    http.set_debug_output $stdout if $DEBUG
    if RUBY_PLATFORM == 'i386-mingw32'
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end
    res = http.start { |http|
      http.request req
    }
    case res
    when Net::HTTPSuccess
      res.body
    else
      raise "Error from #{uri}: #{res.code} #{res.message}"
    end
  end

  def post path, params
    makeRequest POST, path, params
  end

  def get path, params
    makeRequest GET, path, params
  end
end

get '/about' do
  resp = Response.new
  resp.htmlbegin 'About', :nolocate => true
  resp.puts ABOUT_MSG
  resp.htmlend({ :noabout => true, :nologout => true })
  resp.resp
end

# Create a new OAuth2 Client.
def newclient
  Client.new CLIENT_ID, CLIENT_SECRET, CALLBACK_URL, AUTH_URL, ACCESS_URL, API_URL
end

# Check if login cookie is available. If it is, use the access token from
# the database. Otherwise, do the OAuth handshake.
def getclient req, resp
  uuid = req.cookies[TOKEN_COOKIE]
  access_token = nil

  if uuid
    ds = DBConn.get['SELECT token FROM sessions WHERE uuid = ?', uuid]
    row = ds.first
    access_token = row[:token] if row
  end

  client = newclient
  
  if access_token
    client.accessToken = access_token
    return client
  end

  resp.puts 'Not logged in.'
  resp.redirect '/login'
  nil
end

class DBConn
  include Singleton

  def initialize
    @conn = nil
  end

  def get
    unless @conn
      dburl = $DATABASE_URL
      @conn = Sequel.connect dburl
    end
    @conn
  end

  def self.get
    instance.get
  end
end

def set_coords req, lat, lon
  uuid = req.cookies[TOKEN_COOKIE]
  if uuid
    ds = DBConn.get['UPDATE sessions SET coords=? , last_updated=CURRENT_TIMESTAMP WHERE uuid=?', "#{lat.to_f},#{lon.to_f}", uuid]
    ds.update
  end
end


# Get user's coordinates from database. If not found, use default
# coordinates.
def coords req
  lat = nil
  lon = nil

  uuid = req.cookies[TOKEN_COOKIE]
  if uuid
    ds = DBConn.get['SELECT coords FROM sessions WHERE uuid = ?', uuid]
    row = ds.first
    coord_str = row[:coords] if row
    lat, lon = coord_str.split(',') if coord_str
  end

  if !lat || !lon
    lat = DEFAULT_LAT
    lon = DEFAULT_LON
    set_coords req, lat, lon
  end

  [ lat, lon ]
end

# Get the debug setting from cookie. If cookie is not found, assume we are
# not in debug mode.
def get_debug req
  (req.cookies[DEBUG_COOKIE] || 0).to_i != 0
end

# Pretty-print a JSON response.
def debug_json req, resp, jsn
  if get_debug req
    resp.puts "<pre>#{escapeJSON jsn}</pre>"
  end
end


def escapeHTML s
  Rack::Utils::escape_html(s.to_s)
end

def escapeJSON jsn
  escapeHTML PP::pp(jsn, '')
end

def escapeURI s
  Rack::Utils::escape(s.to_s)
end


# Call the Foursquare API. Handle errors. Returns None if there was an
# error. Otherwise, returns the parsed JSON.
def call4sq client, resp, method, path, params={}
  begin
    # Supply a default version.
    params[:v] ||= '20110615'

    result = client.makeRequest method, path, params
    jsn = JSON.parse result

    meta = jsn['meta']
    if meta 
      errorType = meta['errorType']
      errorDetail = meta['errorDetail']

      if errorType == 'deprecated'
        resp.puts "<p><span class=\"error\">Deprecated: #{errorDetail}</span>"              
        return jsn
      end

      if errorType or errorDetail
        resp.errorpage "#{errorType} : #{errorDetail}"
        return 
      end

      return jsn
    end

  rescue => err
    meta = (jsn || {})['meta'] || {}
    errormsg = meta['errorDetail'] || 'Unknown error'
    resp.errorpage <<-EOM
Error from Foursquare API call to #{path}:<br>
#{err}<br>
#{errormsg}<br>
<pre>
#{escapeHTML err.backtrace.join("\n")}
</pre>
    EOM

    return 
  end
end

def conv_a_coord coord, nsew
  coord = coord.to_f

  d = nsew[0..0]
  if coord < 0
    d = nsew[1..1]
    coord = -coord
  end

  "#{d}%02d %06.3f" % [coord.floor, 60 * (coord - coord.floor)]
end

# Convert coordinates from decimal degrees to dd mm.mmm. Returns the result
# as a string.
def convcoords lat, lon
  conv_a_coord(lat, 'NS') + ' ' + conv_a_coord(lon, 'EW')
end


class JsonParseError < RuntimeError
  def initialize msg, jsn = {}
    super msg
    @msg = msg
    @jsn = jsn
  end

  def to_s
    <<-EOM
#{@msg}:<br>
<pre>#{escapeJSON jsn}</pre>
    EOM
  end
end

class NoJsonError < RuntimeError
end

class NoClientError < RuntimeError
end


# Display the logged-in user's icon, name, and position.
def userheader client, resp, lat, lon
  jsn = call4sq client, resp, Client::GET, '/users/self', :v => '20110914'
  return if not jsn

  response = jsn['response']
  raise JsonParseError.new('Missing response from /users/self', jsn) unless response

  user = response['user']
  raise JsonParseError.new('Missing user from /users/self:', jsn) unless user

  firstname = user['firstName'] || ''
  photo = user['photo']

  venueName = ''
  checkins = user['checkins']
  if checkins
    items = checkins['items']
    if items and !items.empty?
      venue = items.first['venue']
      if venue
        venueName = venue['name'] || ''
      end
    end
  end

  resp.puts <<-EOM
<p><img src="#{photo}" alt="" class="usericon" style="float:left">
#{escapeHTML firstname} @ #{escapeHTML venueName}<br>Loc: #{convcoords lat, lon}
<br style="clear:both"> 
  EOM

  return jsn

rescue JsonParseError => err
  warn err.to_s
  return jsn
end

get '/' do
  resp = Response.new
  resp.no_cache

  begin
    lat, lon = coords request
    client = getclient request, resp
    raise NoClientError unless client

    resp.htmlbegin 'Main'

    # Unread notifications count should be in the notification tray in
    # the user query.
    unreadcount = -1
    jsn = userheader client, resp, lat, lon
    if jsn
      notifs = jsn['notifications'] || []
      notifs.each { |notif|
        if notif['type'] == 'notificationTray'
          item = notif['item'] || {}
          unreadcount = item['unreadCount'] || 0
        end
      }
    end

    resp.puts <<-EOM
<script type="text/javascript" src="geocode.js"></script>
<ol class="menulist">

<li><a class="widebutton" href="/geoloc" accesskey="1">Detect location</a></li>

<li><form class="formbox" action="/setloc" onSubmit="box_onsubmit(); return false;" method="get">
Set location: <a href="/setlochelp">[?]</a> <input class="inputbox" type="text" name="newloc" id="newloc" size="16"
accesskey="2"><input class="submitbutton" type="submit" value="Go"></form></li>

<li><a class="widebutton" href="/venues" accesskey="3">Nearest Venues</a></li>

<li><form class="formbox" action="/venues" method="get">
Search Venues: <input class="inputbox" type="text" name="query" size="8"
accesskey="4"><input class="submitbutton" type="submit" value="Search"></form></li>

<li><a class="widebutton" href="/history" accesskey="5">History</a></li>

<li><a class="widebutton" href="/friends" accesskey="6">Find friends</a></li>

<li><form class="formbox" action="/shout" method="post">
Shout: <input class="inputbox" type="text" name="message" size="16" accesskey="7">
<input class="submitbutton" type="submit" value="Shout"></form></li>

<li><a class="widebutton" href="/leader" accesskey="8">Leaderboard</a></li>

<li><a class="widebutton" href="/specials" accesskey="9">Specials</a></li>

<li><a class="widebutton" href="/notif" accesskey="0">Notifications (#{unreadcount})</a></li>

<li><a class="widebutton" href="/badges">Badges</a></li>

<li><a class="widebutton" href="/mayor">Mayorships</a></li>

<li><a class="widebutton" href="/debug">Turn debugging #{get_debug(request) ? 'off' : 'on'}</a></li>

</ol>
    EOM

    debug_json request, resp, jsn
    resp.htmlend
  rescue NoClientError
  end

  resp.resp
end

# Page that we show if the user is not logged in.
get '/login' do
  # This page should be cached. So omit the no_cache() call.
  resp = Response.new
  resp.htmlbegin "Log in", :nolocate => true
  resp.puts <<-EOM
<p>In order to use PlainSq features, you need to log in with Foursquare.
<p><a class="button" href="/login2">Log in with Foursquare</a>
  EOM
  resp.htmlend({ :nologout => true })
  resp.resp
end

# Second part of login handler. This does the actual login and redirection to Foursquare.
get '/login2' do
  resp = Response.new
  resp.puts "Logging in to Foursquare..."
  client = newclient
  resp.redirect client.requestAuth.to_s
  resp.resp
end

# Handler for Debug command. Toggle debug mode.
get '/debug' do
  resp = Response.new
  resp.set_debug !get_debug(request)
  resp.redirect '/'
  resp.resp
end

def name_fmt user
  if user
    escapeHTML "#{user['firstName']} #{user['lastName']}"
  else
    ''
  end
end

# Format a user on the leaderboard page.
def leader_fmt leader
  user = leader['user'] || {}
  scores = leader['scores'] || {}
  <<-EOM
<img src="#{user['photo']}" alt="" class="usericon" style="float:right"><b>#{leader['rank'] || 0}: #{name_fmt user} from #{escapeHTML user['homeCity']}</b><br>
Recent: #{scores['recent'] || 0}<br>
Max: #{scores['max'] || 0}<br>
Checkins: #{scores['checkinsCount'] || 0}<br style="clear:both">
  EOM
end

# Leaderboard handler.
get '/leader' do
  resp = Response.new
  resp.no_cache

  begin
    client = getclient request, resp
    raise NoClientError unless client
    
    jsn = call4sq client, resp, Client::GET, '/users/leaderboard', :neighbors => '20'
    raise NoJsonError unless jsn

    response = jsn['response']
    raise JsonParseError.new('Missing response from /users/leaderboard', jsn) unless response

    leaderboard = response['leaderboard']
    raise JsonParseError.new('Missing leaderboard from /users/leaderboard', jsn) unless leaderboard

    resp.htmlbegin 'Leaderboard'

    count = leaderboard['count'] || 0
    if count > 0
      items = leaderboard['items'] || []
      list = items.map { |item| "<li>#{leader_fmt item}</li>" }.join ''
      resp.puts "<ul class=\"vlist\">#{list}</ul>"
    else
      resp.puts '<p>Empty leaderboard?'
    end

    debug_json request, resp, jsn
    resp.htmlend

  rescue NoClientError

  rescue NoJsonError

  rescue JsonParseError => err
    resp.errorpage err.to_s
  end

  resp.resp
end

get '/setlochelp' do
  resp = Response.new
  # This page should be cached. So omit the no_cache() call.
  resp.htmlbegin 'Set Location Help'
  resp.puts <<-EOM
<p>You can enter either coordinates or a place name / zip code into the 'Set location' input box.
<br>
<br>Enter coordinates as a series of 6 or more digits, e.g.:
<br>
<br>39123457512345 means N 39&deg; 12.345' W 75&deg; 12.345'
<br>391234751234 means N 39&deg; 12.340' W 75&deg; 12.340'
<br>3912375123 means N 39&deg; 12.300' W 75&deg; 12.300'
<br>
<br>In the above input format, PlainSq assumes that the coordinates are in the N/W quadrant. If you need to enter coordinates in another quadrant, specify N/S and E/W in the input string, e.g.:
<br>
<br>N3912345E7512345 means N 39&deg; 12.345' E 75&deg; 12.345'
<br>N391234E751234 means N 39&deg; 12.340' E 75&deg; 12.340'
<br>N39123E75123 means N 39&deg; 12.300' E 75&deg; 12.300'
<br>
<br>Any other input format will be passed to the Google Maps geocoder for interpretation.
  EOM
  resp.htmlend
  resp.resp
end

get '/oauth' do
  resp = Response.new
  resp.no_cache

  auth_code = params[:code]
  client = newclient
  client.requestSession auth_code
  
  access_token = client.accessToken
  uuid = UUID.generate :compact
  
  # Set the login cookie.
  resp.set_cookie TOKEN_COOKIE, uuid

  # Add the access token to the database.
  ds = DBConn.get["INSERT INTO sessions (uuid, token, last_updated) VALUES (?, ?, CURRENT_TIMESTAMP)", uuid, access_token]
  ds.insert

  resp.redirect '/'
  resp.resp
end

# Format the address block of a venue.
def addr_fmt venue
  location = venue['location'] || {}
  contact = venue['contact'] || {}

  s = ''

  addr = location['address']
  s += escapeHTML(addr) + '<br>' if addr

  cross = location['crossStreet']
  s += "(#{escapeHTML cross})<br>" if cross
        
  city = location['city'] || ''
  state = location['state'] || ''
  zip = location['postalCode'] || ''
  country = location['country'] || ''

  if city != '' or state != '' or zip != '' or country != ''
    s += "#{escapeHTML city}, #{escapeHTML state} #{escapeHTML zip} #{escapeHTML country}<br>"
  end

  phone = contact['phone'] || ''
  formattedPhone = contact['formattedPhone']
  phoneStr = if formattedPhone
               formattedPhone
             elsif phone.size > 6
               "(#{phone[0..2]})#{phone[3..5]}-#{phone[6..-1]}"
             else
               nil
             end
  if phone != '' and phoneStr
    s += "<a href=\"tel:#{escapeURI phone}\">#{escapeHTML phoneStr}</a><br>"
  end

  # Discard invalid characters.
  twitter = (contact['twitter'] || '').gsub(/[^a-zA-Z0-9_]/, '')
  if twitter != ''
    s += "<a href=\"http://mobile.twitter.com/#{escapeURI twitter}\">@#{escapeHTML twitter}</a><br>"
  end

  s
end

# Show checkin/moveto links in venue header.
def venue_cmds venue, dist
  dist ||= 9999

  s = ''

  s += <<-EOM
<form style="margin:0; padding:0; display:inline !important;" action="/checkin" method="post">
<input type="hidden" name="vid" value="#{escapeHTML venue['id']}">
<input type="hidden" name="dist" value="#{escapeHTML dist}">
<input class="formbutton" type="submit" value="checkin">
</form>
  EOM

  s += ' <a class="vbutton" href="/checkin_long?%s">checkin with options</a>' % uri_encode_form({
    'vid' => venue['id'], 
    'vname' => venue['name'],
    'dist' => dist,
  })

  location = venue['location']
  if location
    lat = location['lat']
    lng = location['lng']
    if lat and lng
      s += ' <a class="vbutton" href="/coords?%s">move to</a>' % escapeHTML(uri_encode_form({
        'geolat' => lat,
        'geolong' => lng,
      }))
    end
  end

  # Link to venue page on Foursquare regular website.
  s += " <a class=\"vbutton\" href=\"http://foursquare.com/venue/#{escapeURI venue['id']}\">web</a>"

  "<div class=\"buttonbox\">#{s}</div>"
end

def get_prim_category cats
  if cats
    cats.each { |cat|
      return cat if cat['primary']
    }
  end
  nil
end

def mayor_venue_fmt venue, lat, lon
  s = ''
  pcat = get_prim_category venue['categories']
  if pcat
    s += "<table class=\"image\" style=\"float: right\"><caption style=\"caption-side: bottom\">#{escapeHTML pcat['name']}</caption><tr><td><img src=\"#{pcat['icon']}\" alt=\"\"></td></tr></table>"
  end

  dist = nil
  dist_str = ''
  location = venue['location'] || {}
  vlat = location['lat']
  vlon = location['lng']
  if vlat and vlon
    dist = distance lat, lon, vlat, vlon
    compass = bearing lat, lon, vlat, vlon
    dist_str = '(%.1f mi %s)<br>' % [dist, compass]
  end

  s += "<a class=\"button\" href=\"/venue?vid=#{escapeURI venue['id']}\"><b>#{escapeHTML venue['name']}</b></a> #{venue_cmds venue, dist}<br>#{addr_fmt venue}"
  s += dist_str
  s += '<br style="clear:both">'
  s
end

# Mayor handler
get '/mayor' do
  resp = Response.new
  resp.no_cache

  begin
    lat, lon = coords request
    client = getclient request, resp
    raise NoClientError unless client
    
    jsn = call4sq client, resp, Client::GET, '/users/self/mayorships'
    raise NoJsonError unless jsn

    response = jsn['response']
    raise JsonParseError.new('Missing response from /users/self/mayorships', jsn) unless response

    mayorships = response['mayorships']
    raise JsonParseError.new('Missing mayorships from /users/self/mayorships', jsn) unless mayorships

    resp.htmlbegin 'Mayorships'

    count = mayorships['count'] || 0
    if count == 0
      resp.puts '<p>No mayorships yet.'
    else
      items = mayorships['items'] || []
      list = items.map { |item| "<li>#{mayor_venue_fmt(item['venue'] || {}, lat, lon)}</li>" }.join ''
      resp.puts "<ol class=\"numseplist\">#{list}</ol>"
    end

    debug_json request, resp, jsn
    resp.htmlend

  rescue NoClientError

  rescue NoJsonError

  rescue JsonParseError => err
    resp.errorpage err.to_s
  end

  resp.resp
end

def badge_fmt badge
  iconurl = ''
  img = badge['image']
  iconurl = img['prefix'] + img['sizes'][0].to_s + img['name'] if img

  unlockstr = ''
  unlocks = badge['unlocks'] || []
  if unlocks.size > 0
    checkins = unlocks[0]['checkins'] || []
    if checkins.size > 0
      venue = checkins[0]['venue']
      if venue
        location = venue['location']
        city = location['city']
        state = location['state']
        locstr = (city || state) ? " in #{city} #{state}" : ''
        unlockstr = <<-EOM
Unlocked at <a href="/venue?vid=#{escapeURI venue['id']}">#{escapeHTML venue['name']}</a>#{locstr} on #{Time.at(checkins[0]['createdAt']).ctime}.
EOM
      end
    end
  end

  desc = badge['description'] || badge['hint'] || ''
  text = "<b>#{badge['name']}</b><br>#{desc}<br>#{unlockstr}<br style=\"clear:both\">"

  "<img src=\"#{iconurl}\" alt=\"\" style=\"float:right; padding:3px;\">#{text}"
end


# Badges handler.
get '/badges' do
  resp = Response.new
  resp.no_cache

  begin
    client = getclient request, resp
    raise NoClientError unless client
    
    jsn = call4sq client, resp, Client::GET, '/users/self/badges'
    raise NoJsonError unless jsn

    response = jsn['response']
    raise JsonParseError.new('Missing response from /users/self/badges', jsn) unless response

    badges = response['badges']
    raise JsonParseError.new('Missing badges from /users/self/badges', jsn) unless badges

    resp.htmlbegin 'Badges'

    if badges.empty?
      resp.puts '<p>No badges yet.'
    else
      # Sort badges by reverse unlock order.
      # Retain only unlocked badges.
      keys = badges.keys.select { |k| (badges[k]['unlocks'] || []).size > 0 }.sort { |a,b| b <=> a }
      list = keys.map { |k| "<li>#{badge_fmt badges[k]}</li>" }.join ''
      resp.puts "<ol class=\"numseplist\">#{list}</ol>"
    end

    debug_json request, resp, jsn
    resp.htmlend
    
  rescue NoClientError

  rescue NoJsonError

  rescue JsonParseError => err
    resp.errorpage err.to_s
  end

  resp.resp
end

# Format a venue special.
def special_fmt special
  s = "<table class=\"image\" style=\"float: right\"><caption style=\"caption-side: bottom\">#{special['title'] || 'Special Offer'}</caption><tr><td><img src=\"http://foursquare.com/img/specials/#{special['icon'] || 'check-in'}.png\" alt=\"\"></td></tr></table>"

  venue = special['venue']
  s += "<p><a class=\"button\" href=\"/venue?vid=#{escapeURI venue['id']}\"><b>#{escapeHTML venue['name']}</b></a><br>#{addr_fmt venue}" if venue

  message = special['message']
  s += "<br>Message: #{escapeHTML message}" if message

  desc = special['description']
  s += "<br>Description: #{escapeHTML desc}" if desc

  fineprint = special['finePrint']
  s += "<br>Fine print: #{escapeHTML fineprint}" if fineprint

  unlocked = special['unlocked']
  s += "<br>Unlocked: #{escapeHTML unlocked}" if unlocked

  state = special['state']
  s += "<br>State: #{escapeHTML state}" if state

  progress = special['progress']
  s += "<br>Progress: #{escapeHTML progress} #{escapeHTML special['progressDescription']} of #{escapeHTML(special['target'] || 0)}" if progress

  detail = special['detail']
  s += "<br>Detail: #{escapeHTML detail}" if detail

  s + '<br style="clear:both">'
end


# Format venue specials.
def specials_fmt specials, nearby=false
  if specials.empty?
    ''
  else
    list = specials.map { |sp| "<li>#{special_fmt sp}</li>" }.join ''
    "<p><b>Specials#{nearby ? ' nearby' : ''}:</b><ul class=\"vlist\">#{list}</ul>"
  end
end


# Specials handler.
get '/specials' do
  resp = Response.new
  resp.no_cache

  begin
    lat, lon = coords request
    client = getclient request, resp
    raise NoClientError unless client
    
    jsn = call4sq client, resp, Client::GET, '/specials/search', :ll => "#{lat},#{lon}", :limit => 50 
    raise NoJsonError unless jsn

    response = jsn['response']
    raise JsonParseError.new('Missing response from /specials/search', jsn) unless response

    specials = response['specials']
    raise JsonParseError.new('Missing specials from /specials/search', jsn) unless specials

    resp.htmlbegin 'Specials'

    if specials['count'] == 0
      resp.puts '<p>No specials nearby'
    else 
      resp.puts specials_fmt(specials['items'] || [])
    end

    debug_json request, resp, jsn
    resp.htmlend
    
  rescue NoClientError

  rescue NoJsonError

  rescue JsonParseError => err
    resp.errorpage err.to_s
  end

  resp.resp
end

# Returns a time difference in human-readable format.
def fuzzy_delta delta
  if delta < 0
    'in the future?'
  else
    days = (delta / (24 * 60 * 60)).floor
    if days > 1
      "#{days} days ago"
    elsif days == 1
      "1 day ago"
    else
      hours = (delta / (60 * 60)).floor
      if hours > 1
        "#{hours} hours ago"
      elsif hours == 1
        "1 hour ago"
      else
        minutes = (delta / 60).floor
        if minutes > 1
          "#{minutes} minutes ago"
        elsif minutes == 1
          "1 minute ago"
        else
          seconds = delta.floor
          if seconds > 1
            "#{seconds} seconds ago"
          elsif seconds == 1
            "1 second ago"
          else
            "now"
          end
        end
      end
    end
  end
end

def pluralize count, what
  if count == 0
    "no #{what}s"
  elsif count == 1
    "1 #{what}"
  else
    "#{count} #{what}s"
  end
end

def comments_cmd checkin
  comments = checkin['comments'] || {}
  cstr = pluralize(comments['count'] || 0, 'comment')

  photos = checkin['photos'] || {}
  pstr = pluralize(photos['count'] || 0, 'photo')

  "<span class=\"buttonbox\"><a class=\"vbutton\" href=\"/comments?chkid=#{escapeURI checkin['id']}\">#{cstr}, #{pstr}</a></span>"
end

# Format an item from the check-in history.
def history_checkin_fmt checkin, dnow, lat, lon
  s = ''

  venue = checkin['venue']
  if venue 
    id = venue['id']
    # Orphaned venues will be missing the id field.
    s += if id
           dist = nil
           dist_str = ''
           location = venue['location'] || {}
           vlat = location['lat']
           vlon = location['lng']
           if vlat and vlon
             dist = distance lat, lon, vlat, vlon
             compass = bearing lat, lon, vlat, vlon
             dist_str = '(%.1f mi %s)<br>' % [dist, compass]
           end

           "<a class=\"button\" href=\"/venue?vid=#{escapeURI id}\"><b>#{escapeHTML venue['name']}</b></a> #{venue_cmds venue, dist}<br>#{addr_fmt venue}" + dist_str
         else
           "<b>#{escapeHTML venue['name']}</b><br>"
         end
  else
    location = checkin['location']
    s += "<p>#{escapeHTML location['name']} (venueless)<br>" if location 
  end

  shout = checkin['shout']
  s += "\"#{escapeHTML shout}\"<br>" if shout 

  s += "#{comments_cmd checkin}<br>" 

  d1 = Time.at(checkin['createdAt'] || 0)
  s += fuzzy_delta(dnow - d1)

  s
end

# History handler.
get '/history' do
  resp = Response.new
  resp.no_cache

  begin
    lat, lon = coords request
    client = getclient request, resp
    raise NoClientError unless client

    jsn = call4sq client, resp, Client::GET, '/users/self/checkins', :limit => 50 
    raise NoJsonError unless jsn

    response = jsn['response']
    raise JsonParseError.new('Missing response from /users/self/checkins', jsn) unless response

    checkins = response['checkins']
    raise JsonParseError.new('Missing checkins from /users/self/checkins', jsn) unless checkins

    resp.htmlbegin 'History'

    if checkins['count'] == 0
      resp.puts '<p>No check-ins?'
    else
      dnow = Time.now
      items = checkins['items'] || []
      list = items.map { |item| "<li>#{history_checkin_fmt item, dnow, lat, lon}</li>" }.join ''
      resp.puts "<ul class=\"vlist\">#{list}</ul>"
    end

    debug_json request, resp, jsn
    resp.htmlend
    
  rescue NoClientError

  rescue NoJsonError

  rescue JsonParseError => err
    resp.errorpage err.to_s
  end

  resp.resp
end

COMPASS_DIRS = %w[S SW W NW N NE E SE S]

def radians deg
  deg * Math::PI / 180 
end

def degrees rad
  rad * 180 / Math::PI
end

# Compute bearing from (lat, lon) to (vlat, vlon)
# Returns compass direction.
# 
# Adapted from code by Chris Veness (scripts-geo@movable-type.co.uk) at
# http://www.movable-type.co.uk/scripts/latlong.html
def bearing lat, lon, vlat, vlon
  dlon = radians(vlon.to_f - lon.to_f)
  lat1 = radians lat.to_f
  lat2 = radians vlat.to_f

  y = Math.sin(dlon) * Math.cos(lat2)
  x = Math.cos(lat1) * Math.sin(lat2) - Math.sin(lat1) * Math.cos(lat2) * Math.cos(dlon)
  brng = degrees Math.atan2(y, x)

  COMPASS_DIRS[((brng + 180 + 22.5) / 45).floor]
end

# Compute distance from (lat, lon) to (vlat, vlon) using haversine formula.
# Returns distance in miles.
# 
# Adapted from code by Chris Veness (scripts-geo@movable-type.co.uk) at
# http://www.movable-type.co.uk/scripts/latlong.html
def distance lat, lon, vlat, vlon
  earth_radius = 6371 * 1000.0 / METERS_PER_MILE
  dLat = radians(vlat.to_f - lat.to_f)
  dLon = radians(vlon.to_f - lon.to_f)
  lat1 = radians lat.to_f
  lat2 = radians vlat.to_f

  a = Math.sin(dLat/2) * Math.sin(dLat/2) + Math.sin(dLon/2) * Math.sin(dLon/2) * Math.cos(lat1) * Math.cos(lat2) 
  c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a)) 
  earth_radius * c
end


def name_fmt user
  if user
    escapeHTML "#{user['firstName']} #{user['lastName']}"
  else
    ''
  end
end

# Format checkin record from one friend.
def friend_checkin_fmt checkin, lat, lon, dnow
  s = ''

  venue = checkin['venue']
  user = checkin['user']

  user_shown = false

  if venue
    s += "<a class=\"button\" href=\"/venue?vid=#{escapeURI venue['id']}\"><b>#{name_fmt user}</b> @ #{escapeHTML venue['name']}</a><br>"
    user_shown = true
  else
    location = checkin['location'] || {}
    name = location['name']
    if name
      s += "<b>#{name_fmt user}</b> @ #{escapeHTML name}<br>" 
      user_shown = true
    end
  end

  shout = checkin['shout']
  if shout 
    s += "<b>#{name_fmt user}</b> " if not user_shown
    s += "\"#{escapeHTML shout}\"<br>" 
  end

  s += "#{comments_cmd checkin}<br>" 

  if user
    photo = user['photo']
    s += "<img src=\"#{photo}\" alt=\"\" class=\"usericon\" style=\"float:right; padding:3px;\">" if photo
  end

  dist = Float(checkin['distance']) rescue nil
  dist /= METERS_PER_MILE if dist

  location = if venue 
               s += addr_fmt venue
               venue['location'] || {}
             else
               checkin['location'] || {}
             end

  vlat = location['lat']
  vlon = location['lng']

  compass = ''
  if vlat and vlon
    compass = ' ' + bearing(lat, lon, vlat, vlon)
    dist ||= distance(lat, lon, vlat, vlon)
  end

  s += '(%.1f mi%s)<br>' % [dist, compass] if dist 

  d1 = Time.at(checkin['createdAt'] || 0)
  s += fuzzy_delta(dnow - d1)

  source = checkin['source']
  s += "<br>via <a href=\"#{source['url']}\">#{escapeHTML source['name']}</a>" if source

  s += '<br style="clear:both">'

  s
end

# Find Friends handler.
get '/friends' do
  resp = Response.new
  resp.no_cache

  begin
    lat, lon = coords request
    client = getclient request, resp
    raise NoClientError unless client
    
    jsn = call4sq client, resp, Client::GET, '/checkins/recent', :ll => "#{lat},#{lon}", :limit => 100 
    raise NoJsonError unless jsn

    response = jsn['response']
    raise JsonParseError.new('Missing response from /checkins/recent', jsn) unless response

    recent = response['recent']
    raise JsonParseError.new('Missing recent from /checkins/recent', jsn) unless recent

    resp.htmlbegin 'Find Friends'

    dnow = Time.now

    if recent.empty?
      resp.puts '<p>No friends?'
    else
      # Sort checkins by distance. If distance is missing, use a very large
      # value.
      list = recent.sort_by { |v| 
        (v['distance'] || 1000000).to_f 
      }.map { 
        |c| "<li>#{friend_checkin_fmt c, lat, lon, dnow}</li>" 
      }.join ''
      resp.puts "<ul class=\"vlist\">#{list}</ul>"
    end

    debug_json request, resp, jsn
    resp.htmlend
    
  rescue NoClientError

  rescue NoJsonError

  rescue JsonParseError => err
    resp.errorpage err.to_s
  end

  resp.resp
end

def notif_fmt notif
  target = notif['target'] || {}
  targetType = target['type'] || ''
  venue = nil
  checkin = nil

  if targetType == 'tip'
    venue = (target['object'] || {})['venue'] || {}
  elsif targetType == 'checkin'
    checkin = target['object'] || {}
  elsif targetType == 'venue'
    venue = target['object'] || {}
  end

  s = "<a class=\"button\" href=\"/venue?vid=#{escapeURI venue['id']}\">#{escapeHTML venue['name']}</a>" if venue

  s = "<a class=\"button\" href=\"/comments?chkid=#{escapeURI checkin['id']}\">#{escapeHTML(checkin['venue'] || {})['name']}</a>" if checkin

  "<img src=\"#{(notif['image'] || {})['fullPath']}\" alt=\"\" class=\"usericon\" style=\"float:right\"><i>#{Time.at(notif['createdAt'] || 0).ctime}</i><br>#{escapeHTML notif['text']}<br>#{s}<br style=\"clear:both\">"
end

# Notifications handler.
get '/notif' do
  resp = Response.new
  resp.no_cache

  begin
    client = getclient request, resp
    raise NoClientError unless client
    
    jsn = call4sq client, resp, Client::GET, '/updates/notifications', :limit => 50 
    raise NoJsonError unless jsn

    response = jsn['response']
    raise JsonParseError.new('Missing response from /updates/notifications', jsn) unless response

    notifs = response['notifications']
    raise JsonParseError.new('Missing notifications from /updates/notifications', jsn) unless notifs

    jsn2 = nil

    resp.htmlbegin 'Notifications'

    if notifs['count'] == 0
      resp.puts '<p>No notifications yet.'
    else
      items = notifs['items'] || []
      list = items.map { |item| "<li>#{notif_fmt item}</li>" }.join ''

      resp.puts "<ol class=\"numseplist\">#{list}</ol>" 

      hwmark = 0
      hwmark = items[0]['createdAt'] || 0 if items

      resp.puts "<br>Setting highwater mark to #{hwmark}" if get_debug request

      # Mark notifications as read.
      jsn2 = call4sq client, resp, Client::POST, '/updates/marknotificationsread', 'highWatermark' => hwmark 
    end

    debug_json request, resp, jsn
    debug_json request, resp, jsn2
    resp.htmlend
    
  rescue NoClientError

  rescue NoJsonError

  rescue JsonParseError => err
    resp.errorpage err.to_s
  end

  resp.resp
end

# Format a venue in the venue search page.
def venue_fmt venue, lat, lon
  dist = nil
  dist_str = ''
  location = venue['location'] || {}
  vlat = location['lat']
  vlon = location['lng']
  if vlat and vlon
    dist = distance lat, lon, vlat, vlon
    compass = bearing lat, lon, vlat, vlon
    dist_str = '(%.1f mi %s)<br>' % [dist, compass]
  end
  
  s = "<a class=\"button\" href=\"/venue?vid=#{escapeURI venue['id']}\"><b>#{escapeHTML venue['name']}</b></a> #{venue_cmds venue, dist}<br>#{addr_fmt venue}"
  s += dist_str

  s
end

# Format a list of venues in the venue search page.
def venues_fmt jsn, lat, lon
  groups = jsn['groups']
  venues = if groups
             groups.map { |g| g['items'] }.flatten(1)
           else
             jsn['venues'] || []
           end

  # Sort venues ascending by distance. If distance field is missing,
  # use a very large value.
  list = venues.uniq { |v| v['id'] }.sort_by { |v|
    ((v['location'] || {})['distance'] || '1000000').to_f 
  }.map { |v|
    "<li>#{venue_fmt v, lat, lon}</li>"
  }.join ''

  "<ul class=\"vlist\">#{list}</ul>"
end

# Venue Search handler.
get '/venues' do
  resp = Response.new
  resp.no_cache

  begin
    lat, lon = coords request
    client = getclient request, resp
    raise NoClientError unless client
    
    # query is an optional keyword search parameter. If it is not present,
    # then just do a nearest venues search.
    query = params[:query] || ''

    parms = { :ll => "#{lat},#{lon}", :limit => 50, :v => '20110615' }
    parms['query'] = query if query != ''

    jsn = call4sq client, resp, Client::GET, '/venues/search', parms
    raise NoJsonError unless jsn

    response = jsn['response']
    raise JsonParseError.new('Missing response from /venues/search', jsn) unless response

    resp.htmlbegin 'Venue Search'

    resp.puts <<-EOM
<form class="formbox" action="/venues" method="get">
Search Venues: <input class="inputbox" type="text" name="query" size="8"><input class="submitbutton" type="submit" value="Search"></form>
    EOM

    resp.puts "<p>#{venues_fmt response, lat, lon}"

    resp.puts <<-EOM
<form class="formbox" action="/addvenue" method="post">
Not found? Add a venue here and check in:<br><input class="inputbox" type="text" name="vname" size="16"><input class="submitbutton" type="submit" value="Add Venue"></form>
    EOM

    debug_json request, resp, jsn
    resp.htmlend
    
  rescue NoClientError

  rescue NoJsonError

  rescue JsonParseError => err
    resp.errorpage err.to_s
  end

  resp.resp
end

# Static map image.
def map_image lat, lon
    coords = escapeURI "#{lat},#{lon}"
    <<-EOM
<p><img width="250" height="250" alt="[Bing Map]"
src="http://dev.virtualearth.net/REST/v1/Imagery/Map/Road/#{coords}/14?ms=250,250&pp=#{coords};0&key=Aha1lOg_Dx1TU7quU-wNTgDN3K3fI9d4MYRgNGIIX1rQI7SBHs4iLB6LRnbKFN5c">
    EOM
#   parms = uri_encode_form({
#     'size' => '250x250', 
#     'format' => 'gif',
#     'sensor' => 'false',
#     'zoom' => '14',
#     'markers' => "size:mid|color:blue|#{lat},#{lon}"
#   })
#   "<p><img width=\"250\" height=\"250\" alt=\"[Google Map]\" src=\"http://maps.google.com/maps/api/staticmap?#{parms}\">"
end

def category_fmt cat
  path = (cat['parents'] + [ cat['name'] ]).join ' / '
  "<p><img src=\"#{cat['icon']}\" alt=\"\" style=\"float:left\">#{escapeHTML path}<br style=\"clear:both\">"
end

# Format the info about a user checked in at this venue.
def venue_checkin_fmt checkin, dnow
    s = "<p><img src=\"#{checkin['user']['photo']}\" alt=\"\" class=\"usericon\" style=\"float:left\">#{name_fmt checkin['user']} from #{escapeHTML checkin['user']['homeCity']}"

    shout = checkin['shout']
	s += "<br>\"#{escapeHTML shout}\"" if shout 

    d1 = Time.at(checkin['createdAt'] || 0)
    s += "<br>#{fuzzy_delta dnow - d1}"

    s + '<br style="clear:both">'
end

def photo_fmt photo, dnow, parms
  venue_id = parms[:venue_id]
  checkin_id = parms[:checkin_id]

  imgurl = photo['url']

  # If multiple sizes are available, then pick the largest photo that is not
  # greater than 150 pixels in width. If none fit, pick the smallest photo.
  if photo['sizes']['count'] > 0
    _photos = photo['sizes']['items'].select { |p| p['width'] <= 150 }
    img = if _photos.empty?
            photo['sizes']['items'].min_by { |p| p['width'] }
          else
            _photos.max_by { |p| p['width'] }
          end
    imgurl = img['url']
  end

  photoparms = { 'photoid' => photo['id'] }
  if venue_id
    photoparms['venid'] = venue_id
  else
    photoparms['chkid'] = checkin_id
  end
  photourl = '/photo?' + uri_encode_form(photoparms)

  "<p>#{name_fmt photo['user']}:<br><a href=\"#{photourl}\"><img src=\"#{imgurl}\" alt=\"\"></a><br>(#{fuzzy_delta(dnow - Time.at(photo['createdAt'] || 0))})<br>"
end

# Format a tip on the venue page.
def tip_fmt tip
  "<p><img src=\"#{tip['user']['photo']}\" alt=\"\" class=\"usericon\" style=\"float:left\">#{name_fmt tip['user']} from #{escapeHTML tip['user']['homeCity']} says: #{escapeHTML tip['text']} (Posted: #{Time.at(tip['createdAt'] || 0).ctime})<br style=\"clear:both\">"
end

# Format a list of tips on the venue page.
def tips_fmt tips
  if tips['count'] > 0
    list = tips['groups'].map { |grp|
      grp['items'].map { |t| tip_fmt t  }.join '' 
    }.join ''
    "<p><b>Tips:</b>#{list}"
  else
    ''
  end
end

# Format info on a venue.
def vinfo_fmt venue, lat, lon
  dnow = Time.now

  gmap_str = ''
  dist_str = ''
  dist = nil
  location = venue['location'] || {}
  vlat = location['lat']
  vlon = location['lng']
  if vlat and vlon
    # Add static map image to the page.
    gmap_str = map_image(vlat, vlon)

    dist = distance lat, lon, vlat, vlon
    compass = bearing lat, lon, vlat, vlon
    dist_str = '(%.1f mi %s)<br>' % [dist, compass]
  end

  s = "<p>#{escapeHTML venue['name']} #{venue_cmds venue, dist}<br>#{addr_fmt venue}"
  s += dist_str

  url = venue['url']
  s += "<br><a href=\"#{url}\">#{escapeHTML url}</a>" if url

  s += gmap_str

  cats = venue['categories'] || []
  s += cats.map { |c| category_fmt c }.join ''

  tags = venue['tags'] || []
  s += "<p>Tags: #{escapeHTML tags.join(', ')}" unless tags.empty?

  stats = venue['stats']
  s += "<p>Checkins: #{escapeHTML stats['checkinsCount']} <br>Users: #{escapeHTML stats['usersCount']}" if stats 
  beenhere = venue['beenHere']
  s += "<br>Your checkins: #{escapeHTML beenhere['count']}" if beenhere 

  herenow = venue['hereNow']
  s += "<br>Here now: #{escapeHTML herenow['count']}" if herenow 

  venue_mayor = venue['mayor']
  mayor = venue_mayor ? venue_mayor['user'] : nil

  s += "<p><img src=\"#{mayor['photo']}\" alt=\"\" class=\"usericon\" style=\"float:left\">#{name_fmt mayor} (#{escapeHTML venue_mayor['count']}x) from #{escapeHTML mayor['homeCity']} is the mayor<br style=\"clear:both\">" if mayor

  if herenow and herenow['count'] > 0
    s += '<p><b>Checked in here:</b>'
    s += (herenow['groups'] || []).map { |g|
      (g['items'] || []).map { |c| venue_checkin_fmt c, dnow }.join ''
    }.join ''
  end

  s += tips_fmt(venue['tips'] || [])
  s += specials_fmt(venue['specials'] || [])
  s += specials_fmt(venue['specialsNearby'] || [], true)

  photos = venue['photos']
  count = (photos ? photos['count'] : 0) || 0

  s += if count == 0
         '<p>-- No photos --'
       else
         photos['groups'].map { |group|
           "<p>-- #{escapeHTML group['name']}: #{escapeHTML group['count']} --" + group['items'].map { |p|
             photo_fmt p, dnow, :venue_id => venue['id']
           }.join('')
         }.join ''
       end

  s += <<-EOM
<p>
<form style=\"margin:0; padding:0;\" enctype=\"multipart/form-data\" action=\"/addphoto\" method=\"post\">
<input type=\"file\" name=\"photo\"><br>
<input type=\"hidden\" value=\"#{escapeHTML venue['id']}\" name=\"venid\">
<input type=\"submit\" value=\"Add JPEG photo\"><br>
</form>
  EOM

  s
end

# Venue Info handler.
get '/venue' do
  resp = Response.new
  resp.no_cache

  begin
    lat, lon = coords request
    client = getclient request, resp
    raise NoClientError unless client
    
    vid = params[:vid] || ''      
    if vid == ''
      resp.redirect '/'
    else
      jsn = call4sq client, resp, Client::GET, "/venues/#{escapeURI vid}"
      raise NoJsonError unless jsn

      response = jsn['response']
      raise JsonParseError.new('Missing response from /venues', jsn) unless response

      venue = response['venue']
      raise JsonParseError.new('Missing venue from /venues', jsn) unless venue

      resp.htmlbegin 'Venue Info'

      resp.puts vinfo_fmt(venue, lat, lon)

      debug_json request, resp, jsn
      resp.htmlend
    end

  rescue NoClientError

  rescue NoJsonError

  rescue JsonParseError => err
    resp.errorpage err.to_s
  end

  resp.resp
end

# Logout handler.
get '/logout' do
  resp = Response.new
  resp.del_cookie TOKEN_COOKIE
  resp.del_cookie DEBUG_COOKIE
  resp.htmlbegin 'Logout', :nolocate => true
  resp.puts '<p>You have been logged out'
  resp.htmlend({ :nologout => true })
  resp.resp
end

def photo_full_fmt photo, params
  venue_id = params[:venue_id]
  checkin_id = params[:checkin_id]
  backurl = if venue_id
              "/venue?vid=#{escapeURI venue_id}"
            else
              "/comments?chkid=#{escapeURI checkin_id}"
            end
  "<p><a href=\"#{backurl}\"><img src=\"#{photo['url']}\" alt=\"\"></a><br>"
end
	    
# View full-size version of a photo.
get '/photo' do
  resp = Response.new
  resp.no_cache

  begin
    client = getclient request, resp
    raise NoClientError unless client

    checkin_id = params[:chkid] || ''
    venue_id = params[:venid] || ''
    photo_id = params[:photoid] || ''
    if photo_id == ''
      resp.redirect '/'
    else
      jsn = call4sq client, resp, Client::GET, "/photos/#{escapeURI photo_id}"
      raise NoJsonError unless jsn

      response = jsn['response']
      raise JsonParseError.new('Missing response from /photos', jsn) unless response

      photo = response['photo']
      raise JsonParseError.new('Missing photo from /photos', jsn) unless photo

      resp.htmlbegin 'Photo'
      resp.puts(photo_full_fmt photo, :checkin_id => checkin_id, :venue_id => venue_id)

      debug_json request, resp, jsn
      resp.htmlend
    end
  rescue NoClientError

  rescue NoJsonError

  rescue JsonParseError => err
    resp.errorpage err.to_s
  end

  resp.resp
end

# Add a photo to a check-in.
post '/addphoto' do
  resp = Response.new
  resp.no_cache

  begin
    client = getclient request, resp
    raise NoClientError unless client
    
    checkin_id = params[:chkid] || ''
    venue_id = params[:venid] || ''
    photo = params[:photo] || {}

    if checkin_id == '' and venue_id == ''
      resp.redirect '/'
    else
      resp.htmlbegin 'Photo Upload'

      tmpfile = photo[:tempfile]
      filename = photo[:filename]

      if not tmpfile or not filename
        resp.puts "No image selected for upload."
      else
#         imglist = Magick::Image.from_blob tmpfile.read
#         img = imglist.first
#         img.format = 'JPEG'
#         img.change_geometry!('800x800') { |cols, rows, img|
#           img.resize! cols, rows
#         }

        img = MiniMagick::Image.read(tmpfile.read)
        img.format 'JPEG'
        img.resize '800x800'
        parms = { :photo => img.to_blob }
        if venue_id != ''
          parms[:venueId] = venue_id
        else
          parms[:checkinId] = checkin_id
        end

        jsn = call4sq client, resp, Client::POST, '/photos/add', parms
        raise NoJsonError unless jsn

        if venue_id != ''
          resp.redirect "/venue?vid=#{escapeURI venue_id}"
        else
          resp.redirect "/comments?chkid=#{escapeURI checkin_id}"
        end
      end

      debug_json request, resp, jsn
      resp.htmlend
    end

  rescue NoClientError

  rescue NoJsonError

  rescue JsonParseError => err
    resp.errorpage err.to_s
  end

  resp.resp
end

def del_comment_cmd checkin, comment
  "<a class=\"vbutton\" href=\"/delcomment?chkid=#{escapeURI checkin['id']}&commid=#{escapeURI comment['id']}\">delete</a>"
end

def comment_fmt comment, checkin, dnow
  "<p>#{name_fmt comment['user']}: #{escapeHTML comment['text']} (#{fuzzy_delta dnow - Time.at(comment['createdAt'] || 0)})<br>#{del_comment_cmd checkin, comment}<br>"
end

def checkin_comments_fmt checkin, lat, lon
  s = ''
  dnow = Time.now
  s += "<p></p>#{history_checkin_fmt checkin, dnow, lat, lon}"

  s += "<p>-- #{pluralize checkin['comments']['count'], 'comment'} --"
  if checkin['comments']['count'] > 0
    s += checkin['comments']['items'].map { |c|
      comment_fmt c, checkin, dnow
    }.join ''
  end

  s += "<p>-- #{pluralize checkin['photos']['count'], 'photo'} --"
  if checkin['photos']['count'] > 0
    s += checkin['photos']['items'].map { |c|
      photo_fmt c, dnow, :checkin_id => checkin['id']
    }.join ''
  end

  s
end

# View comments on a check-in.
get '/comments' do
  resp = Response.new
  resp.no_cache

  begin
    lat, lon = coords request
    client = getclient request, resp
    raise NoClientError unless client
    
    checkin_id = params[:chkid] || ''
    if checkin_id == ''
      resp.redirect '/'
    else
      jsn = call4sq client, resp, Client::GET, "/checkins/#{escapeURI checkin_id}"
      raise NoJsonError unless jsn

      response = jsn['response']
      raise JsonParseError.new('Missing response from /checkins', jsn) unless response

      checkin = response['checkin']
      raise JsonParseError.new('Missing checkin from /checkins', jsn) unless checkin


      resp.htmlbegin 'Checkin Comments'

      resp.puts checkin_comments_fmt(checkin, lat, lon)

      resp.puts <<-EOM
<p>
<form style="margin:0; padding:0;" action="/addcomment" method="post">
<input class="inputbox" type="text" name="text" size="15"><br>
<input type="hidden" value="#{escapeHTML checkin_id}" name="chkid">
<input class="formbutton" type="submit" value="Add comment"><br>
</form>
      EOM

      resp.puts <<-EOM
<p>
<form style="margin:0; padding:0;" enctype="multipart/form-data" action="/addphoto" method="post">
<input class="inputbox" type="file" name="photo"><br>
<input type="hidden" value="#{escapeHTML checkin_id}" name="chkid">
<input class="formbutton" type="submit" value="Add JPEG photo"><br>
</form>
      EOM

      debug_json request, resp, jsn
      resp.htmlend
    end
    
  rescue NoClientError

  rescue NoJsonError

  rescue JsonParseError => err
    resp.errorpage err.to_s
  end

  resp.resp
end

# Delete a comment from a check-in.
get '/delcomment' do
  resp = Response.new
  resp.no_cache

  begin
    client = getclient request, resp
    raise NoClientError unless client

    checkin_id = params[:chkid] || ''
    comment_id = params[:commid] || ''

    if checkin_id == '' or comment_id == ''
      resp.redirect '/'
    else
      jsn = call4sq client, resp, Client::POST, "/checkins/#{escapeURI checkin_id}/deletecomment", :commentId => comment_id
      raise NoJsonError unless jsn

      resp.redirect "/comments?chkid=#{escapeURI checkin_id}"
    end

  rescue NoClientError

  rescue NoJsonError

  rescue JsonParseError => err
    resp.errorpage err.to_s
  end

  resp.resp
end

# Add a comment to a check-in.
post '/addcomment' do
  resp = Response.new
  resp.no_cache

  begin
    client = getclient request, resp
    raise NoClientError unless client

    checkin_id = params[:chkid] || ''
    text = params[:text] || ''

    if checkin_id == '' 
      resp.redirect '/'
    elsif text != ''
      jsn = call4sq client, resp, Client::POST, "/checkins/#{escapeURI checkin_id}/addcomment", :text => text
      raise NoJsonError unless jsn

      resp.redirect "/comments?chkid=#{escapeURI checkin_id}"
    end

  rescue NoClientError

  rescue NoJsonError

  rescue JsonParseError => err
    resp.errorpage err.to_s
  end

  resp.resp
end


# This handles user-input coordinates. Sets the location to those
# coordinates and brings up the venue search page.
get '/coords' do
  resp = Response.new
  resp.no_cache

  geolat = Float(params[:geolat]) rescue nil
  geolong = Float(params[:geolong]) rescue nil

  if geolat and geolong
    set_coords request, geolat, geolong
    resp.redirect '/venues'
  else
    resp.redirect '/'
  end

  resp.resp
end

def find_notifs notif, ntype
  notif.select { |n| n['type'] == ntype }.map { |n| n['item'] }
end

# Shout handler
post '/shout' do
  resp = Response.new
  resp.no_cache

  begin
    lat, lon = coords request
    client = getclient request, resp
    raise NoClientError unless client

    message = params[:message] || ''      
    if message == ''
      resp.redirect '/'
    else
      jsn = call4sq client, resp, Client::POST, "/checkins/add", :shout => message, :ll => "#{lat},#{lon}", :broadcast => 'public'
      raise NoJsonError unless jsn

      notif = jsn['notifications']
      raise JsonParseError.new('Missing notifications from /checkins/add', jsn) unless notif

      resp.htmlbegin 'Shout'

      msgs = find_notifs notif, 'message'
      resp.puts "<p>#{escapeHTML msgs[0]['message']}" unless msgs.empty?

      debug_json request, resp, jsn
      resp.htmlend
    end

  rescue NoClientError

  rescue NoJsonError

  rescue JsonParseError => err
    resp.errorpage err.to_s
  end

  resp.resp
end

# Geolocation Handler with GPS monitoring and refresh. Uses HTML5
# Geolocation API.
get '/geoloc' do
  # This page should be cached. So omit the no_cache() call.
  resp = Response.new
  resp.htmlbegin 'Detect Location'
  resp.puts <<-EOM
<noscript>
<p><span class="error">No Javascript support or Javascript disabled.</span> Can't detect location.</p>
</noscript>
<p><span id="output">&nbsp;</span><span id="error">&nbsp;</span>
<p><span id="map">&nbsp;</span>
<script type="text/javascript" src="lib.js"></script>
<script type="text/javascript" src="geoloc.js"></script>
  EOM
  resp.htmlend
  resp.resp
end

def deg_min st
  deg = st[0..1]
  min = st[2..-1]
  if min == ''
    min = '0'
  end
  if min.size > 2
    min = min[0..1] + '.' + min[2..-1]
  end
  [deg, min]
end

# Parse user-entered coordinates.
# This function handles the case where coordinates are entered as digits
# only. The string is split into two halves. The first half fills in dd
# mm.mmm in the latitude and the second half fills in dd mm.mmm in the
# longitude. These coordinates are assumed to be in the N/W quadrant.
def parse_coord_digits coordstr
  mid = (coordstr.size + 1) / 2
  latstr = coordstr[0..mid-1]
  lonstr = coordstr[mid..-1]

  d, m = deg_min latstr
  lat = "%.6f" % (d.to_i + m.to_f / 60.0)

  d, m = deg_min lonstr
  lon = "%.6f" % -(d.to_i + m.to_f / 60.0)

  [lat, lon]
end


# Parse user-entered coordinates.
# This function is the same as parse_coord_digits but also allows the user
# to enter N or S and E or W. For example, the user can enter something
# like NddddddEdddddd for coordinates in the N/E quadrant.
def parse_coord_nsew matchObj
  sign = 1
  if matchObj[1].upcase == 'S'
    sign = -1
  end
  d, m = deg_min matchObj[2]
  lat = "%.6f" % (sign * (d.to_i + m.to_f / 60.0))

  sign = 1
  if matchObj[3].upcase == 'W'
    sign = -1
  end
  d, m = deg_min matchObj[4]
  lon = "%.6f" % (sign * (d.to_i + m.to_f / 60.0))

  [lat, lon]
end

# Parse user-entered coordinates.
def parse_coord coordstr
  if coordstr.match(/^\d{6,}$/)
    return parse_coord_digits coordstr
  end

  m = coordstr.match(/^([NS])(\d{3,})([EW])(\d{3,})$/i)
  if m
    return parse_coord_nsew m
  end

  nil
end

# Client-side version of SetlocHandler. If Javascript is enabled, use this
# to avoid hitting Geocoding API quotas.
get '/setlocjs' do
  # This page should be cached. So omit the no_cache() call.
  resp = Response.new
  resp.htmlbegin 'Set Location'
  resp.puts <<-EOM
<noscript>
<p><span class="error">No Javascript support or Javascript disabled.</span> Can't set location.</p>
</noscript>
<p><span id="error"></span><span id="output"></span>
<form class="formbox" action="/setloc" onSubmit="box_onsubmit(); return false;" method="get">
Search again? <input class="inputbox" type="text" name="newloc" id="newloc"
size="16"><input class="submitbutton" type="submit" value="Go"></form>
<script type="text/javascript" src="http://maps.googleapis.com/maps/api/js?sensor=false"></script>
<script type="text/javascript" src="lib.js"></script>
<script type="text/javascript" src="geocode.js"></script>
  EOM

  newloc = (params[:newloc] || '').strip
  coords = parse_coord newloc
  if coords
    lat, lon = coords
    set_coords request, lat, lon
    resp.redirect '/venues'
  else
    resp.puts <<-EOM
<script type="text/javascript">
window.onload = do_geocode('#{escapeHTML newloc}');
</script>
    EOM
  end

  resp.htmlend
  resp.resp
end

def geocode_result_fmt result
  addr = result['formatted_address'] || ''
  geometry = result['geometry'] || {}
  location = geometry['location'] || {}
  lat = location['lat'] || 0
  lng = location['lng'] || 0

  s = "<a class=\"button\" href=\"/coords?%s\">#{escapeHTML addr}</a>" % uri_encode_form({
    'geolat' => lat,
    'geolong' => lng
  })
  s += "<br>#{convcoords lat, lng}"
  s += map_image(lat, lng)
  s
end

# This handles the 'set location' input box. If the locations string is six
# or more digits, it will be parsed as user-input coordinates. Otherwise,
# it will be fed to the Google Geocoding API.
get '/setloc' do
  resp = Response.new
  resp.no_cache
  resp.htmlbegin 'Set Location'

  newloc = (params[:newloc] || '').strip
  coords = parse_coord newloc
  if coords
    lat, lon = coords
    set_coords request, lat, lon
    resp.redirect '/venues'
  else
    uri = URI 'http://maps.googleapis.com/maps/api/geocode/json'
    uri.query = uri_encode_form :sensor => 'false', :address => newloc

    http = Net::HTTP.new uri.host, uri.port
    res = http.start { |http|
      http.request Net::HTTP::Get.new uri.request_uri
    }

    case res
    when Net::HTTPSuccess
      jsn = JSON.parse res.body

      status = jsn['status'] || ''
      status = 'Unknown Error' if status == ''
      if status != 'OK' and status != 'ZERO_RESULTS'
        resp.errorpage "Error from Google Geocoding API: #{status}"
      else
        results = jsn['results'] || []
        if results.empty?
          resp.puts '<p>No search results.'
        else
          list = results.map { |res| "<li>#{geocode_result_fmt res}</li>" }.join ''
          resp.puts "<p>Did you mean?<ul class=\"vlist\">#{list}</ul>"
        end

        resp.puts <<-EOM
<form class="formbox" action="/setloc" method="get">
Search again? <input class="inputbox" type="text" name="newloc" size="16"><input class="submitbutton" type="submit" value="Go"></form>
        EOM

      end
    else
      resp.errorpage "Error #{res.code} from Geocoding API call to #{uri}: #{res.message}"
    end
  end

  resp.htmlend
  resp.resp
end

def checkin_badge_fmt badge
  iconurl = ""
  img = badge['image']
  iconurl = img['prefix'] + img['sizes'][0].to_s + img['name'] if img

  <<-EOM
<p><img src="#{iconurl}" alt="" style="float:left">
You've unlocked the #{badge['name']} badge: 
#{badge['description']}<br style="clear:both">
  EOM
end

def checkin_score_fmt score
  <<-EOM
<p><img src="#{score['icon']}" alt="" style="float:left">
#{score['points']} points: #{score['message']}<br style="clear:both">
  EOM
end

def checkin_ldr_row_fmt leader
  user = leader['user'] || {}
  scores = leader['scores'] || {}
  <<-EOM
<p><img src="#{user['photo']}" alt="" class="usericon" style="float:left"> ##{leader['rank'] || 0}: #{user['firstName']} #{user['lastName']} from #{user['homeCity']}<br>
#{scores['recent']} points, #{scores['checkinsCount']} checkins, #{scores['max']} max<br style="clear:both">
  EOM
end

def checkin_ldr_fmt leaderboard
  s = ''

  leaders = leaderboard['leaderboard'] || []
  s += leaders.map { |l| checkin_ldr_row_fmt l }.join ''

  s += "<p>#{leaderboard['message']}"
  s
end

# Format checkin messages.
def checkin_fmt checkin, notif
  msgs = find_notifs notif, 'message'
  s = "<p>#{escapeHTML msgs[0]['message']}" unless msgs.empty?

  venue = checkin['venue']
  if venue 
    s += "<p><a class=\"button\" href=\"/venue?vid=#{escapeURI venue['id']}\">#{escapeHTML venue['name']}</a><br>#{addr_fmt venue}"

    location = venue['location']
    if location 
      lat = location['lat']
      lng = location['lng']
      # Add static map image to the page.
      s += map_image(lat, lng) if lat and lng 
    end

    pcat = get_prim_category venue['categories']
    s += category_fmt(pcat) if pcat 
  end

  mayors = find_notifs notif, 'mayorship'
  if mayors.size > 0
    mayor = mayors[0]

    msg = escapeHTML mayor['message']
    user = mayor['user']
    s += if user
           "<p><img src=\"#{user['photo']}\" alt=\"\" class=\"usericon\" style=\"float:left\">#{msg}<br style=\"clear:both\">"
         else
           "<p>#{msg}"
         end
  end

  badges = find_notifs notif, 'badge'
  s += badges[0].values.map { |b| checkin_badge_fmt b }.join '' if badges.size > 0

  scores = find_notifs notif, 'score'
  s += scores[0]['scores'].map { |score| checkin_score_fmt score }.join '' if scores.size > 0

  specials = find_notifs notif, 'special'
  s += specials.map { |item| '<p>' + special_fmt(item['special'] || {}) }.join '' if specials.size > 0

  leaderboard = find_notifs notif, 'leaderboard'
  s += checkin_ldr_fmt(leaderboard[0]) if leaderboard.size > 0

  s
end

def do_checkin request, resp, client, vid, useloc = false
  begin
    lat, lon = coords request

    params = { :venueId => vid, :broadcast => 'public' }
    params['ll'] = "#{lat},#{lon}" if useloc

    jsn = call4sq client, resp, Client::POST, '/checkins/add', params
    raise NoJsonError unless jsn

    response = jsn['response']
    raise JsonParseError.new('Missing response from /checkins/add', jsn) unless response

    checkin = response['checkin']
    raise JsonParseError.new('Missing checkin from /checkins/add', jsn) unless checkin

    notif = jsn['notifications']
    raise JsonParseError.new('Missing notifications from /checkins/add', jsn) unless notif

    resp.htmlbegin 'Check in'

    resp.puts checkin_fmt(checkin, notif)

    debug_json request, resp, jsn
    resp.htmlend
    
  rescue NoJsonError

  rescue JsonParseError => err
    resp.errorpage err.to_s
  end
end

# This handles user checkins by venue ID.
post '/checkin' do
  resp = Response.new
  resp.no_cache

  begin
    client = getclient request, resp
    raise NoClientError unless client

    vid = params[:vid] || ''      
    if vid == ''
      resp.redirect '/'
    else
      dist = Float(params[:dist]) rescue 9999
      useloc = dist < MAX_MILES_LOC
      do_checkin request, resp, client, vid, useloc
    end

  rescue NoClientError

  end

  resp.resp
end

# This handles user checkin with options.
get '/checkin_long' do
  resp = Response.new
  resp.no_cache

  begin
    client = getclient request, resp
    raise NoClientError unless client
    
    vid = params[:vid] || ''      
    vname = params[:vname] || ''      
    dist = params[:dist] || ''

    jsn = call4sq client, resp, Client::GET, "/settings/all"
    raise NoJsonError unless jsn

    response = jsn['response']
    raise JsonParseError.new('Missing response from /settings/all', jsn) unless response

    settings = response['settings']
    raise JsonParseError.new('Missing settings from /settings/all', jsn) unless settings

    priv = false
    twitter = settings['sendToTwitter']
    facebook = settings['sendToFacebook']

    resp.htmlbegin 'Check In'
    resp.puts "<p>Check in @ #{escapeHTML vname}"

    sel = 'selected="selected"'
    resp.puts <<-EOM
<form action="/checkin_long2" method="post">
Shout (optional): <input class="inputbox" type="text" name="shout" size="15"><br>
<input type="hidden" value="#{escapeHTML vid}" name="vid">
<input type="hidden" value="#{escapeHTML dist}" name="dist">
<input class="formbutton" type="submit" value="check-in"><br>
<select name="private">
<option value="1" #{priv ? sel : ''}>Don't show your friends</option>
<option value="0" #{priv ? '' : sel}>Show your friends</option>
</select><br>
<select name="twitter">
<option value="0" #{twitter ? '' : sel}>Don't send to Twitter</option>
<option value="1" #{twitter ? sel : ''}>Send to Twitter</option>
</select><br>
<select name="facebook">
<option value="0" #{facebook ? '' : sel}>Don't send to Facebook</option>
<option value="1" #{facebook ? sel : ''}>Send to Facebook</option>
</select><br>
</form>
    EOM

    debug_json request, resp, jsn
    resp.htmlend

  rescue NoClientError

  rescue NoJsonError

  rescue JsonParseError => err
    resp.errorpage err.to_s
  end

  resp.resp
end

# Continuation of /checkin_long handler after the user submits the checkin
# form with options.
post '/checkin_long2' do
  resp = Response.new
  resp.no_cache

  begin
    lat, lon = coords request
    client = getclient request, resp
    raise NoClientError unless client
    
    vid = params[:vid] || ''      
    if vid == ''
      resp.redirect '/'
    else
      dist = Float(params[:dist]) rescue 9999
      useloc = dist < MAX_MILES_LOC

      shout = params[:shout].to_s
      priv = params[:private].to_i != 0
      twitter = params[:twitter].to_i != 0
      facebook = params[:facebook].to_i != 0

      broadstrs = []
      broadstrs << (priv ? 'private' : 'public')
      broadstrs << 'twitter' if twitter
      broadstrs << 'facebook' if facebook

      params = { :venueId => vid, :shout => shout, :broadcast => broadstrs.join(',') }
      params['ll'] = "#{lat},#{lon}" if useloc

      jsn = call4sq client, resp, Client::POST, '/checkins/add', params
      raise NoJsonError unless jsn

      response = jsn['response']
      raise JsonParseError.new('Missing response from /checkins/add', jsn) unless response

      checkin = response['checkin']
      raise JsonParseError.new('Missing checkin from /checkins/add', jsn) unless checkin

      notif = jsn['notifications']
      raise JsonParseError.new('Missing notifications from /checkins/add', jsn) unless notif

      resp.htmlbegin 'Check In'

      resp.puts checkin_fmt(checkin, notif)

      debug_json request, resp, jsn
      resp.htmlend
    end

  rescue NoClientError

  rescue NoJsonError

  rescue JsonParseError => err
    resp.errorpage err.to_s
  end

  resp.resp
end

post '/addvenue' do
  resp = Response.new
  resp.no_cache

  begin
    lat, lon = coords request
    client = getclient request, resp
    raise NoClientError unless client

    vname = params[:vname] || ''      
    if vname == ''
      resp.redirect '/'
    else
      jsn = call4sq client, resp, Client::POST, "/venues/add", :name => vname, :ll => "#{lat},#{lon}"
      raise NoJsonError unless jsn

      response = jsn['response']
      raise JsonParseError.new('Missing response from /venues/add', jsn) unless response

      venue = response['venue']
      raise JsonParseError.new('Missing venue from /venues/add', jsn) unless venue

      do_checkin request, resp, client, venue['id'], true
    end

  rescue NoClientError

  rescue NoJsonError

  rescue JsonParseError => err
    resp.errorpage err.to_s
  end

  resp.resp
end

# Purge old database table entries.
get '/purge' do
  resp = Response.new
  resp.no_cache
  resp.htmlbegin 'Purge old database entries'

  date_threshold = (Date.today -30).strftime '%Y-%m-%d'

  ds = DBConn.get["DELETE FROM sessions WHERE last_updated < '#{date_threshold}'"]
  rows = ds.delete

  resp.puts "#{rows} rows deleted."

  resp.htmlend
  resp.resp
end

# --- The End ---
