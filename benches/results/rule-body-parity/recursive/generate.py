"""Generate benign JSON documents without recursive Python objects."""
from pathlib import Path
import json

def repeat(left, right, leaf, levels):
    return left * levels + leaf + right * levels

def cases():
    array = {"$defs":{"list":{"anyOf":[{"type":"integer"},{"type":"array","items":{"$ref":"#/$defs/list"}}]}},"$ref":"#/$defs/list"}
    obj = {"$ref":"#/$defs/node","$defs":{"node":{"anyOf":[{"type":"null"},{"type":"object","properties":{"next":{"$ref":"#/$defs/node"}}, "required":["next"],"additionalProperties":False}]}}}
    mutual = {"$ref":"#/$defs/value","$defs":{"value":{"if":{"type":"object"},"then":{"required":["v"],"properties":{"v":{"$ref":"#/$defs/list"}}},"else":{"const":0}},"list":{"type":"array","maxItems":1,"items":{"$ref":"#/$defs/value"}}}}
    siblings = {"$schema":"https://json-schema.org/draft/2020-12/schema","$defs":{"n":{"if":{"type":"array"},"then":{"items":{"$ref":"#/$defs/n","not":{"const":12}}},"else":{"enum":[12,24]}}},"$ref":"#/$defs/n"}
    root = {"if":{"type":"array"},"then":{"minItems":1,"items":{"$ref":"#"}},"else":{"type":"string","pattern":"^ok$"}}
    pointer = {"$defs":{"a/b":{"anyOf":[{"type":"boolean"},{"type":"array","items":{"$ref":"#/$defs/a~1b"}}]}},"$ref":"#/$defs/a~1b"}
    dynamic = {"$schema":"https://json-schema.org/draft/2020-12/schema","$dynamicAnchor":"node","if":{"type":"array"},"then":{"items":{"$dynamicRef":"#node"}},"else":{"type":"integer"}}
    tagged = {"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"#/$defs/node","$defs":{"node":{"anyOf":[{"type":"null"},{"type":"object","allOf":[{"properties":{"child":{"$ref":"#/$defs/node"}},"required":["child"]}],"unevaluatedProperties":False}]}}}
    for name,schema,left,right,good,bad in (
        ('dynamic',dynamic,'[',']','42','"bad"'),
        ('evaluated',tagged,'{"child":','}','null','{"child":null,"unused":true}'),
        ('array',array,'[',']','42','"word"'),
        ('object',obj,'{"next":','}','null','{}'),
        ('mutual',mutual,'{"v":[',']}','0','true'),
        ('siblings',siblings,'[',']','24','12'),
        ('root',root,'[',']','"ok"','"wrong"'),
        ('pointer',pointer,'[',']','false','0'),
    ):
        for n in (1,24,160):
            for leaf,invalid in ((good,False),(bad,True)):
                yield (f'{name}/{n}/{"invalid" if invalid else "valid"}',schema,repeat(left,right,leaf,n),invalid)
    yield ('array/boundary', array, repeat('[',']','42',10000),False)
    yield ('array/above-boundary', array, repeat('[',']','42',10001),True)

if __name__ == '__main__':
    p=Path(__file__).resolve().parent
    (p/'cases.jsonl').write_text(''.join(json.dumps([name,json.dumps(schema,separators=(',',':')),doc,invalid],separators=(',',':'))+'\n' for name,schema,doc,invalid in cases()))
