# Developer Documentation

Autopsy has a very detailed developer's guide located here:
https://www.sleuthkit.org/autopsy/docs/api-docs/4.1/.

If you have never worked with TLSH before, check out the TLSH website
(https://tlsh.org/) and GitHub (https://github.com/trendmicro/tlsh), which goes
in depth about TLSH and how to use it.

- [Developer Documentation](#developer-documentation--developer-documentation)
  - [Environment Setup](#environment-setup)
  - [Ingest Module Architecture](#ingest-module-architecture)
    - [TlshIngestModuleFactory](#tlshingestmodulefactory)
    - [TlshFileIngestModule](#tlshfileingestmodule)
    - [TlshModuleIngestJobSettings](#tlshmoduleingestjobsettings)
    - [TlshIngestModuleIngestJobSettingsPanel](#tlshingestmoduleingestjobsettingspanel)
    - [TlshIngestModuleGlobalSettingsPanel](#tlshingestmoduleglobalsettingspanel)
    - [CreateTlshHashSetDialog](#createtlshhashsetdialog)
    - [MimeTypeComparison](#mimetypecomparison)
    - [ParseTlshFromStrings](#parsetlshfromstrings)
- [Editing GUIs](#editing-guis)
- [Testing](#testing)
- [Java Specific Documentation](#java-specific-documentation)
  - [Array of Strings from an Object](#array-of-strings-from-an-object)
- [Future Work](#future-work)
  - [File Reading Improvement](#file-reading-improvement)

## Environment Setup

In order to develop on this plug-in, Java 1.8 and the NetBeans Java IDE is
required. The specifics on how to build Autopsy and .nbm files are detailed
here: https://www.sleuthkit.org/autopsy/docs/api-docs/4.1/mod_dev_page.html.

The Netbeans IDE can be found at: https://netbeans.apache.org//

Oracles guide on how to install Java on your desired platform can be found here:
https://docs.oracle.com/javase/8/docs/technotes/guides/install/install_overview.html

## Ingest Module Architecture

Autopsy has detailed documentation and a sample ingest module located here:
https://www.sleuthkit.org/autopsy/docs/api-docs/4.1/mod_ingest_page.html. This
documentation will focus more on the specifics of this ingest module.

### TlshIngestModuleFactory

The [`TlshIngestModuleFactory`](../src/org/mitre/tlshmodule/TlshIngestModuleFactory.java)
is what Autopsy uses to initialize the plug-in. This file is where everything 
gets initialized and points Autopsy to the file ingest class, the settings
panels, and the module display information. The only thing that a developer
should have to modify in this panel is version number or description.

### TlshFileIngestModule

This is the core of the file ingest logic.
Whenever Autopsy starts an ingest, it initializes an instance of the class,
which should handle transferring all the settings to local private variables
inside the class. This is important to do because if another ingest is started
with different settings it will mess up any currently running ones. If new
settings are added, it should be done here.
Next, Autopsy runs the
[`startUp():91`](../src/org/mitre/tlshmodule/TlshFileIngestModule.java)
function which does any logic that needs to be handled before running the
ingest. For example, it currently converts all the string version of the hashes
to `Tlsh` objects that can be compared.

After all the initialization steps are completed it runs the
[`process():135`](../src/org/mitre/tlshmodule/TlshFileIngestModule.java)
function to handle the hashing and comparisons. It runs `process()` on each
file that is being analyzed. 
Currently, each file is being checked if it is an actual system file, then is
checked if it is the correct MIME type that the user selected, and finally
generating the hash. If there is a comparison selected, the ingest will compare
the file hash to all the provided hashes. 

To help with processing speed, the file is not analyzed if it is of the
incorrect MIME file type. The module also checks if the TLSH hash was already
calculated for that file and uses that instead of recalculating. 

The module also uses helper functions from separate classes to help organize
the code as follows:
* MimeTypeComparison
* ParseTlshFromStrings

### TlshModuleIngestJobSettings

This file hosts all the settings that are available for an ingest. If a
developer needs to add new settings to the plug-in then it should be done here.
All new settings need to have a getter and setter function so that the other
classes can access them. Whenever adding a new setting it is recommended to
have it set to a non-null default value. 

### TlshIngestModuleIngestJobSettingsPanel

This contains the GUI code and logic for the per ingest settings of the plug-in.
All major GUI modifications should take place in the NetBeans IDE design editor
(more about that in the Editing GUIs section). Anything that is as simple as
adding or removing rows from a table can take place in the
[`customizeComponents():253`](../src/org/mitre/tlshmodule/TlshIngestModuleIngestJobSettingsPanel.java)
function.

The `customizeComponents()` function takes in the previously used settings and
applies them to the components. If more settings are added this is where they
could be graphically displayed to the user.

The [`getSettings():74`](../src/org/mitre/tlshmodule/TlshIngestModuleIngestJobSettingsPanel.java)
function is the function that returns the currently selected settings to Autopsy
to start the ingest with. If any new settings are added to the
`TlshModuleIngestJobSettings` class, then it will also need to be updated here.

A final note that is unique about the settings panel is its ability to update
off of the global settings that are currently set. This gets implemented by
making the class an `ActionListener` and adding the
[`actionPerformed():221`](../src/org/mitre/tlshmodule/TlshIngestModuleIngestJobSettingsPanel.java)
function to the class. Once per second the plug-in checks for updates to the
global settings, which are hash sets. If the global settings are different, the
hash set table updates its hashes. If a developer adds more functionality to the
global settings panel and needs it to be reflected to this settings panel, that
should take place in the `actionPerformed()` function.

### TlshIngestModuleGlobalSettingsPanel

The global settings panel is where hash sets can be entered in either manually
or imported. The created hash sets will be shared across the current Autopsy
instance. Similar to the previous settings panel all the modifications should
take place in the NetBeans GUI editor and customization of these components
should take place in the `customizeComponents()` function.

The implementation of saving the hash sets is with the Autopsy `ModuleSettings`
class(https://sleuthkit.org/autopsy/docs/api-docs/4.19.0//_module_settings_8java_source.html).
This tells Autopsy to create and write settings to a config file that it can
easily parse so that it can be used for later. Due to limitations of the
settings it can only handle a map with the string as the key and the entry as a
string. Using the `ModuleSettings` class allows for the per ingest settings
panel to read and update its table as well as the actual file ingest to read and
use the hash sets as well.

The global settings panel also uses the `CreateTlshHashSetDialog` to create the
popup to allow creating and editing of hash sets.

### CreateTlshHashSetDialog

This is a Java swing `JDialog` class that allows for it to be called upon to
create a popup to modify or create hash sets. If it is creating then it allows
the user to input a name that will be used to save the hash set to the
`ModuleSettings` class and therefore useable by the rest of the program. If it
is editing then it pulls that information to be modified by the user while not
allowing them to modify the name of the `ModuleSetting`.

### MimeTypeComparison

Currently, this class has only one static function. The function takes strings
which represent file MIME types. It then returns true or false based on if they
match. The `compareType` variable can contain wild cards on either side (`*`) to
allow for more broad matching to take place.  

If new functionality is needed that is related to MIME types of a file or
comparing MIME types, then it should be implemented here. 

### ParseTlshFromStrings

This class contains a single static function that is used to parse out hashes
from the saved hash sets or other strings. The string that is passed should be a
digest that was saved or used by the quick search functionality. It then returns
a string array with hashes that can be used for processing.

Currently, it only supports one hash per line, ignores blank lines, and comments
that are done with `#` or `//` symbols. The symbols can be on their own line, or
trailing a hash. If more comment types or different parsing is needed, then it
should be modified or added here. Currently, comments can be made with the `#`
or the `//` symbols.

# Editing GUIs

NetBeans has a design editor for any Java class that has a form file. Anything
in this program that has a GUI element to it has been created with a `.form`
file in order to be edited. This can be done by going to the Java class and
clicking the `Design` tab next to the `Source` tab at the top of the code
editing window. New elements can be added from the `Palette` on the right.
Properties of each component can be modified by either right-clicking on them or
single clicking on them to show them in the settings panel on the right below
the `Palette`. If the component needs to be modified with `ModuleSettings`
values, then it should take place in a
[`customizeComponents():253`](../src/org/mitre/tlshmodule/TlshIngestModuleIngestJobSettingsPanel.java)
section inside the source code. Double-clicking on the component will create an
action listener or button click depending on the component. 

One thing to be careful of when editing or creating GUIs with the editor is the
constraints that get added to the components. This can sometimes not behave as
they seem and will make certain elements of the GUI look misshapen when not
handled properly. 

# Testing

Any non-Autopsy functions that are made that can be tested should be tested.
Currently, the only functions being tested are the `MimeTypeComparison` and the
`ParseTlshFromStrings` functions. Tests for a Java class in NetBeans can be
created by right-clicking the `.java` file and navigating to
`Tools -> Create/Update Tests`. A test file will then be automatically generated
and added to the `Unit Test Packages`.

# Java Specific Documentation

## Array of Strings from an Object
When using `.toArray()` on an object such as an `ArrayList<String>` in Java,
it does not get properly converted to a string array when just casting. In order
to properly cast the `Object[]` the developer needs to do the following:

``` Java
// Taken from https://stackoverflow.com/questions/4042434/converting-arrayliststring-to-string-in-java
String[] strArr = variableName.toArray(new String[0]);
```

# Future Work

## File Reading Improvement
In the `TlshFileIngestModule.java` beginning at line 246 there is a try-catch
statement in
[`calculateTlshHash():242`](../src/org/mitre/tlshmodule/TlshFileIngestModule.java).
There maybe some improvement that can be done on the reading in of files to
memory. Currently the entire length of the buffer (the file) is read into
memory. This has not caused any known issues yet but there may be a better more
efficient way to handle this. There was an attempt initially made to read 
portions of the file one at a time, but was causing errors in the software
output.