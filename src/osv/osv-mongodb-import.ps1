# This is a Windows Powershell script that you can use to import the entire
# OSV.dev for querying
#
# The OSV data dump is here:
#   https://storage.googleapis.com/osv-vulnerabilities/index.html
# The file you want to download is all.zip
# (if it moves, the OSV.dev documentation should show you)
#
# Unzip that all.zip (I recommend 7-zip instead of Windows' built-in zip)
#
# Set the path to the directory containing the JSON/CSV files
$directoryPath = "C:\Users\Andy\Downloads\all"

# Set the MongoDB connection details. You'll need to create this db first
$mongoHost = "localhost"
$mongoPort = 27017
$mongoDatabase = "osv"
$mongoCollection = "all"

Get-ChildItem $directoryPath -Filter "*.json" | ForEach-Object {
    $filePath = $_.FullName
    mongoimport --uri "mongodb://localhost:27017" --db $mongoDatabase --collection $mongoCollection --type json --file $filePath
}

# This may take SEVERAL HOURS to import. Yeah, MongoDB sucks at that part.
# While it's importing, grab a cup of coffee and read about the json schema
# here: https://ossf.github.io/osv-schema