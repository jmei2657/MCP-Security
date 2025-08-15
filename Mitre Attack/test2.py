import json
with open('data/enterprise-attack.json') as json_data:
     d = json.load(json_data)
     objects = d["objects"]
     print(len(objects))
     attack_obj = []
     for ob in objects:
          if ob["type"] == "attack-pattern":
               attack_obj.append(ob)
     print(set([a["type"] for a in objects]))
     print(len(attack_obj))
     result = []
     for ob in attack_obj:
          a = {}
          result.append({'name' : ob['name'], 'description' : ob['description'], 'mitre-id' : ob['external_references'][0]['external_id']})
     # print(result[:2])
     with open("results.json", 'w') as json_file:
          json_file.write(json.dumps(result, indent=4))