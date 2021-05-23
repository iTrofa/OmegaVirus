import json


with open('report.json') as json_data:
    data_dict = json.load(json_data)

print(float(data_dict["info"]["score"]))

for i in data_dict["info"]:
    if i!="score":
        print(str(i) + "  --  " + str(data_dict["info"][i]))
