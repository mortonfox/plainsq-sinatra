require 'rubygems'
require 'sequel'
require './setup.rb'

DB = Sequel.connect($DATABASE_URL)
stmt = <<-EOM
CREATE TABLE sessions ( 
  uuid VARCHAR(100) PRIMARY KEY,
  token VARCHAR(100),
  coords VARCHAR(100),
  last_updated TIMESTAMP 
)
EOM
DB.run stmt
