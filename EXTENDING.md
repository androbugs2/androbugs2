# Extending AndroBugs Framework
In order to add your own vectors to the AndroBugs Framework, please copy
the `example_vector.py` file to the `vectors` directory and modify and rename it to match
the vulnerabilities you want to look for.

See Androguard's documentation for the available functionality.  https://androguard.readthedocs.io/en/latest/intro/gettingstarted.html

- `self.apk` refers to Androguard's apk object
- `self.dalvik` refers to Androguard's dvm object
- `self.analysis` refers to Androguard's Analysis object

Use the provided `self.writer` to start writing output. Please see `writer.py` for available methods. 
To retrieve target sdk  and minimum skd version numbers use `self.target_sdk` and `self.target_min_sdk` respectively.
Use `self.args` to access the `ConfigParser` arguments defined in `androbugs.py@parseArgument`.
 