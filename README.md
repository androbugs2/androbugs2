# AndroBugs Framework

AndroBugs Framework is an Android vulnerability analysis system that helps developers or hackers find potential security vulnerabilities in Android applications. 
No splendid GUI interface, but the most efficient (less than 2 minutes per scan in average) and more accurate.

Version: 2.0.0

## Features
- Find security vulnerabilities in Android applications
- Check if an application's code is lacking best practices
- Detect if an application uses a certain cross-platform development framework (such as Xamarin, Flutter, or React Native)
- Check if an application executes potentially dangerous shell commands (e.g. “su”)
- Parallel massive analysis feature to scan large numbers of applications in a short amount of time (allows to scan 1000 applications on a machine with 20 cores and 10 GB RAM in under 15 minutes)
- Check an app’s security protections (marked as ```<Hacker>```, designed for app repackaging hacking)
- Find and decode base64 encoded strings
- Easy development and integration of new vulnerability vectors (see [EXTENDING.md](EXTENDING.md))


## Setup
The following requirements are needed in order to fully use AndroBugs Framework's features:
- Python 3
- MongoDB installation (https://www.mongodb.org/downloads) 

The MongoDB installation is necessary if you want to use the massive analysis fetaure. 

Clone the repository to a local folder.  In this folder, create a virtual environment: `python3 -m venv venv` and activate the virtual environment: `source venv/bin/activate`

Install the required packages by running `pip -r requirements.txt`. (It is possible to use pip and python instead of pip3 and python3 since we have activated the virtual environment.) The required packages will be installed locally in the folder `./venv/lib/python3.7/site-packages`

Optionally reconfigure the MongoDB config in `androbugs-db.cfg` to match your MongoDB configuration. The database will be created if it does not exists already.

## Usage for Unix/Linux

### Running the AndroBugs Framework
To scan an application for all the defined vulnerabilities run the following command:
```
python androbugs.py -f [APK file]
```
Optionally, you can specify which vectors you would like to scan, using 
```
python androbugs.py -f [APK file] -d [Vector Name]
```
For example, you could replace `[Vector Name]` with `STRANDHOGG_2` to only scan the application for the Strandhogg 2.0 vulnerability.

To get a full list of defined vulnerabilities, please run the following command:
```
python androbugs.py -l
```

### Getting help for parameters

```
python androbugs.py -h
```

### Usage of Massive Analysis Tools for Unix/Linux

```
python AndroBugs_MassiveAnalysis.py -b [Analysis Date] -t [Anaysis Tag] -d [APKs input directory] -o [Report output directory]
```
 
Example:
```
python AndroBugs_MassiveAnalysis.py -b 30072020 -t BlackHat -d ~/APKDataset/ -o ~/Massive_Analysis_Reports
```


### To get the summary report and all the vectors of massive analysis

```
python AndroBugs_ReportSummary.py -m massive -b [Analysis Date] -t [Anaysis Tag]
```

Example:
```
python AndroBugs_ReportSummary.py -m massive -b 30072020 -t BlackHat
```


### Listing potentially vulnerable apps by Vector ID and Severity Level (Log Level)

```
python AndroBugs_ReportByVectorKey.py -v [Vector ID] -l [Log Level] -b [Analysis Date] -t [Anaysis Tag]
python AndroBugs_ReportByVectorKey.py -v [Vector ID] -l [Log Level] -b [Analysis Date] -t [Anaysis Tag] -a
```

Example:
```
python AndroBugs_ReportByVectorKey.py -v WEBVIEW_RCE -l Critical -b 30072020 -t BlackHat
python AndroBugs_ReportByVectorKey.py -v WEBVIEW_RCE -l Critical -b 30072020 -t BlackHat -a
```

![AndroBugs_ReportSummary.py](http://www.androbugs.com/images/v1.0.0/MassiveAnalysisTool2.png)

![AndroBugs_ReportByVectorKey.py](http://www.androbugs.com/images/v1.0.0/MassiveAnalysisTool1.png)

## Authors
[Original](https://github.com/AndroBugs/AndroBugs_Framework) (v1.0.0):
- Yu-Cheng Lin ([@AndroBugs](https://github.com/AndroBugs))

Improved (v2.0.0):
- Jasper van Thuijl ([@jvthuijl](https://github.com/jvthuijl))
- Noam Drong ([@ndrong](https://github.com/ndrong))

## Licenses

* AndroBugs Framework is under the license of [GNU GPL v3.0](http://www.gnu.org/licenses/gpl-3.0.txt)

