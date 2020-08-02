#######################
# Script to compare which applications are detected for a specific vector between two AndroBugs massive analysis results.
#
# ARGUMENTS:
# $1 build of first analysis
# $2 tag of first analysis
# $3 build of second analysis
# $4 tag of second analysis
# $5 vector e.g. SSL_WEBVIEW
# $6 warning level to compare e.g. Critical

module load Python/3.6.6-foss-2018b
A=$(python AndroBugs_ReportByVectorKey.py -b $1 -t $2 -v $5 -l $6)
B=$(python AndroBugs_ReportByVectorKey.py -b $3 -t $4 -v $5 -l $6)
A=$(sed '1,5d' <(echo "$A") | head -n -4)
B=$(sed '1,5d' <(echo "$B") | head -n -4)
comm -23 <(echo "$A" | sort) <(echo "$B" | sort)