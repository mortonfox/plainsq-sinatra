# Purge old sessions from table.

require 'rubygems'
require 'sequel'
require './setup.rb'
require 'date'

date_threshold = (Date.today - 30).strftime '%Y-%m-%d'
stmt = "DELETE FROM `sessions` WHERE `last_updated` < ?"
Sequel.connect($DATABASE_URL) { |db|
  rows = db[stmt, date_threshold].delete
  puts "#{rows} rows deleted."
}
