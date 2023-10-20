# TLSH Autopsy Plug-in 

An ingest module plug-in for Autopsy that can be used to analyze TLSH hashes
and compare them to known TLSH hash sets.

The official TLSH java library from Trend Micro was utilized in this plug-in.
The GitHub repository can be found [here](https://github.com/trendmicro/tlsh).
Version 4.5.0 was used in this plug-in and can be found in the
`release/modules/ext` directory. If a newer version of the TLSH library is 
desired, it can be  built from the official repository and replaced.

> **Note**
> If a newer version of the library is being use be sure to update the file in
> the NetBeans build options and also test the plug-in for full functionality.

## Installation 

### From Releases 

1. Navigate to the releases and download the `org-mitre-tlshmodule.nbm` file to
your desired location.  

2. Open Autopsy application 

3. Go to Tools > Plugins > Downloaded (Tab) > Add Plugins... (Button) 

4. Navigate to the `org-mitre-tlshmodule.nbm` file that was downloaded earlier
and navigate the installation wizard to finish install. 

5. Verify installation by moving to the Installed tab and verify that the
`TlshModule` is active. 

### From Source 

1. Clone down the repo and open the NetBeans Module in NetBeans IDE. 

2. Build the module project by right-clicking on the module project
(`TlshModule`) and click `Create NBM`. 

4. The `.nbm` module will be built to the `build/` directory. 

5. Open Autopsy application 

6. Go to Tools > Plugins > Downloaded (Tab) > Add Plugins... (Button) 

7. Navigate to the `org-mitre-tlshmodule.nbm` file that was built earlier and
navigate the installation wizard to finish install. 

8. Verify installation by moving to the Installed tab and verify that the
`TlshModule` is active. 

## Usage 

### Generating Hashes 

These steps apply if you simply want to generate TLSH hash values for all
files, or for a subset based on MIME type.  First, add a new data source to a
new or existing case.  Alternatively, if the data source is already added,
select Tools -> Run Ingest Modules. Enable the TLSH Ingest Module and
optionally filter by MIME type to calculate the initial hashes of all the
files. Once the ingest is complete, all the files can be found under
`Analysis Results > Interesting Files > `
`TLSH (Trend Micro Locality Sensitive Hash)`. The files under this section
will have the TLSH hash value attached and other meta-data.  

### Entering Named Known Hash Sets 

This section describes how to manage hash sets for use in the comparison
process. While configuring the TLSH Ingest Module click on `Global Settings`.
Options include: 

**Create Hash Set** - manually paste the hash set values in to create a hash
set.  

> Note, this new hash set is localized for this instance of Autopsy. 
> Note, the plug-in can handle comments with a `#` or `//` and new lines if
needed between hashes if needed. The comments can also be done inline with the
hash to be displayed in the results.

**Import Hash Set** - import a hash set from a standard text file. 

> Note, there must be one hash, comment, or newline per line. The plug-in does
not know how to read more than one hash per line, but can handle a comment on
the same line as a hash. Multiple hash sets can be imported if a folder is
selected. The plug-in will recursively go through the folders getting all the
`.txt` files.

**Edit Hash Set** – add or remove hashes from the hash set.  

> Note, the resulting hash set does not alter the file if previously imported.
> Note, this modified hash set is localized for this instance of Autopsy.

**Export Hash Set** - exports all selected hash lists to a directory on disk.

> Note, it saves them all as a .txt file.

**Refresh From Disk** - reloads all the hash sets that were imported from disk.
It is an easy way to make changes to files on disk and then apply those changes
in Autopsy.

**Refresh Selected Files From Disk** - reloads the selected hash sets that were
imported from disk. It is an easy way to make changes to files on disk and then
apply those select changes in Autopsy

**Delete Hash Set** – remove the selected hash set or sets from the local
instance of Autopsy. 

### Comparison 

There are multiple settings in the TLSH Module for running comparisons with
other TLSH hashes.  

**Threshold distance** – max distance for a comparison to be considered a
“hit”. 

**Include file length in comparison** – should the length of the file be taken
into consideration when comparing the files? Here is a summarized snippet from
the TLSH official documentation that provides more details: 

``` 
The length difference specifies if the file length is to be included in the
difference calculation or if it is to be excluded. In general, the length
should be considered in the difference calculation, but there could be
applications where a part of the adversarial activity might be to add a lot of
content. For example, to add 1 million zero bytes at the end of a file. In that
case, the caller would want to exclude the length from the calculation. 
``` 

**MIME File Type to compare to** – limit processing to a specific MIME file
type. This can speed up the ingestion of files by only running the hashing on
specific types of files. 

> Note, if the desired MIME file type is not found in the list, a custom one
can be inputted by double-clicking and typing what is desired into the input
box. Wild cards are supported on entire sides (ex: `image/*` not `image/jp*`).

**TLSH Quick Search** – for a quick search of a list of hashes. 

> Note, these hashes will not be saved.

**Known Hash Sets to Compare to** – select the hash sets you want to use for
comparison. These are managed under `Global Settings`. 

Once all the selections are made, run the TLSH ingest (press Finish). All
comparisons that fit the distance and MIME filter will be displayed under
`Analysis Results > Interesting Files > TLSH Comparison Hits - <A UUID>` and be
added to a compounding list at
`Analysis Results > Interesting Files > TLSH Comparison Hits`. Each comparison
hit will show the distance from the matching value and either the hash or name
of the hash set that it matched with. Each ingest that is run will also get its
own group that is labeled with a UUID so that it is identifiable. If a comment
was inline with the hash, then it will also be displayed as well.

# Remarks 

## Different TLSH Hashes  

There are two different types of TLSH hashes in the code: ORIGINAL and
VERSION_4. The VERSION_4 includes a "T1" header and the ORIGINAL does not. Here
is a snippet from the TLSH GitHub repo explaining the difference
(https://github.com/trendmicro/tlsh): 

``` 
We have added a version identifier ("T1") to the start of the digest so that we
can clearly distinguish between different variants of the digest (such as
non-standard choices of 3 byte checksum). This means that we do not rely on the
length of the hex string to determine if a hex string is a TLSH digest (this is
a brittle method for identifying TLSH digests). We are doing this to enable
compatibility, especially backwards compatibility of the TLSH approach. 

The code is backwards compatible, it can still read and interpret 70 hex
character strings as TLSH digests. And data sets can include mixes of the old
and new digests. If you need old style TLSH digests to be outputted, then use
the command line option '-old' 
``` 

The plug-in defaults to VERSION_4, but the comparisons work with hash values
using the ORIGINAL type as well. 

## Logging

All TLSH ingest module failures are logged to the central Autopsy log file. The
Autopsy documentation describes the different places that logs can be output
depending on the build type
(https://wiki.sleuthkit.org/index.php?title=Autopsy_3_Logging_and_Error_Checking).
The release logs should be located in the follow locations:

``` bash
${USER_HOME}/.autopsy                           # Linux
C:/Users/${USERNAME}/AppData/Roaming/.autopsy   # Windows
```

# NOTICE

© 2023 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number: 23-2044.