#!/usr/bin/env python
"""script to check if there was more findings in last sast analysis"""
import sys
import json
import csv
import xml.etree.ElementTree as ET

# this script assumes that the row (linter,number) exists in csv file

def extract_number_baseline(filename: str, linter: str) -> int:
    """ open baseline file and extract the number of findings in the row
        that matches 'linter'
    """
    try:
        count = 0
        with open(filename, newline='', encoding="utf-8") as basefile:
            content = csv.reader(basefile)
            for row in content:
                if row[0] == linter:
                    for i in range(1, len(row)): # low medium high critical
                        count = count + int(row[i])
                        print(row[i], count)
            return count
    except OSError:
        print ("Could not open/read file:", filename)
        sys.exit()


def extract_number_json(filename: str)-> int:
    """extract number of findings in json semgrep report file"""
    try:
        with open(filename, 'r', encoding="utf-8", errors="ignore") as semgrep_json_file:
            semgrep_json = json.load(semgrep_json_file)
            return len(semgrep_json['results'])
    except OSError:
        print ("Could not open/read file:", filename)
        return -1


def extract_number_json_pip_audit(filename: str)-> int:
    """extract number of findings in json semgrep report file"""
    try:
        with open(filename, 'r', encoding="utf-8", errors="ignore") as json_file:
            semgrep_json = json.load(json_file)
            return len(semgrep_json['dependencies'])
    except OSError:
        print ("Could not open/read file:", filename)
        return -1


def extract_number_sarif(filename: str)-> int:
    """extract number of findings in sarif semgrep report file"""
    try:
        with open(filename, 'r', encoding="utf-8", errors="ignore") as semgrep_sarif_file:
            semgrep_sarif = json.loads(semgrep_sarif_file.read())
            return len(semgrep_sarif.get("runs")[0].get("results"))
    except OSError:
        print ("Could not open/read file:", filename)
        return -1


def extract_number_xml(filename: str) -> int:
    try:
        tree = ET.parse('semgrep.xml')
        root = tree.getroot()
        count = int(root.attrib.get("failures")) + int(root.attrib.get("errors"))
        return count    
    except ET.ParseError:
        print ("Could not open/read file:", filename)
        return -1
    except OSError:
        print ("Could not open/read file:", filename)
        return -1                


def there_are_more_findings(baseline, new_report) -> int:
    """compare if there is more findings or not"""
    result = 0 # No
    if baseline < new_report:
        result = 1 # Yes
    return result


def main(basefile: str, new_report: str, linter: str)-> int:
    """main function"""
    number_findings_new_report : int = -1
    
    if new_report.endswith("sarif"):
        number_findings_new_report = extract_number_sarif(new_report)

    else:
        if linter == "bandit":
            if new_report.endswith("json"):
                number_findings_new_report = extract_number_json(new_report)
            else:
                print("File with reports should be json or sarif, and have extension .json, .sarif, or .xml")
                return(-1)
    
        if linter == "semgrep":
            if new_report.endswith("json"):
                number_findings_new_report = extract_number_json(new_report)
            elif new_report.endswith("xml"):
                number_findings_new_report = extract_number_xml(new_report)
            else:
                print("File with reports should be json or sarif, and have extension .json, .sarif, or .xml")
                return(-1)
        
        if linter == "pip-audit":
            if new_report.endswith("json"):
                number_findings_new_report = extract_number_json_pip_audit(new_report)
            else:
                print("File with reports should be json or sarif, and have extension .json, .sarif, or .xml")
                return(-1)
    
    print("number offindings in new report", number_findings_new_report)
    if number_findings_new_report == -1:
        print("Error trying to open file: " + new_report)
        sys.exit(1)
    baseline_number : int = extract_number_baseline(basefile, linter)
    print("baseline number of findings", baseline_number)
    exit_code : int = there_are_more_findings(baseline_number, number_findings_new_report)
    print("exit code:", exit_code)
    return(exit_code)
    return(-1)


if __name__ == "__main__":
    if len(sys.argv) == 4:
        baseline_file : str = sys.argv[1]
        linter_report : str = sys.argv[2]
        linter_name : str = sys.argv[3]
        exit_code = main(baseline_file, linter_report, linter_name)
        sys.exit(exit_code)
    else:
        print("Usage: ./compare_findings baseline new_semgrep_report")
        sys.exit(1)
