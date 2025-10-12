from datetime import datetime

unix_timestamp = int(input("Enter the Unix timestamp: "))


dt_object = datetime.fromtimestamp(unix_timestamp)
print(dt_object)