# Set the path to the directory containing the JSON/CSV files
$directoryPath = "C:\code\nvdcve\nvdcve\"

# Set the MongoDB connection details
$mongoHost = "localhost"
$mongoPort = 27017
$mongoDatabase = "nvdcve"
$mongoCollection = "nvdcve"

Get-ChildItem $directoryPath -Filter "*.json" | ForEach-Object {
    $filePath = $_.FullName
    mongoimport --uri "mongodb://localhost:27017" --db $mongoDatabase --collection $mongoCollection --type json --file $filePath
}
