import json
from preprocessor import PythonPreprocessor
from detector import VulnerabilityDetector
p = PythonPreprocessor()
d = VulnerabilityDetector()
funcs = p.preprocess_file("test_upload.py")
print("Functions found:", len(funcs))
for f in funcs:
    print("Function:", f["name"])
    print("Code:", repr(f["code"]))
    res = d.predict(f)
    print("Is vuln:", res["is_vulnerable"])
    print("Prob:", res["confidence"])

