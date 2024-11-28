# cloud-credentials-insights

CCI (Cloud Credentials Insights) is a couple of helper tools to extract insights from credential requests to cloud providers on OpenShift environments.

Tools:
- cci.py: must work in vanila python with minimum dependencies
- cci-donwloader.py (TODO)

## How it works?

CCI works specially parsing data from the logs from Cloud Provider API
calls focusing in IAM identities used by OpenShift components during the
cluster lifecycle.

The CCI extracts the audit logs, filtering and transforming to a query format
to discover identities used by OpenShift components, such as installer, and cloud
controllers and operators (such as: machine, image registry, CCO, CSI, etc) from
CredentialsRequests manifests available in the release payload of the cluster version.

## Supported platforms

- AWS using a CloudTrail configured in the region you are looking to collect/parse the events.

## Requirements

- AWS CloudTrail enabled collecting audit logs from API calls

## Installing

Copy `cci.py` to your path.

```sh
export CCI=~/bin/cci
wget -O $CCI https://raw.githubusercontent.com/openshift-splat-team/cloud-credentials-insights/refs/heads/devel-cci-aws/cci.py
```

## Usage

### Collect events from CloudTrail

Collect data from CloudTrail from any desired timestamp.

The following example

> WARNING: the following example would download a lot of data depending of the amount of logs you have stored. We advice you to filter the `AWS_TRAIL_BUCKET_NAME` by appending the object path to the bucket name to download only data from the time window desired.

```sh
aws s3 sync s3://"${AWS_TRAIL_BUCKET_NAME}"" "${EVENTS_PATH_RAW}"/
```

Where:

- `AWS_TRAIL_BUCKET_NAME`: the bucket name that CloudTrail is saving event logs. Example: `trail-bucket`, or with object path `trail-bucket/AWSLogs/${ACCOUNT_ID}/CloudTrail/${REGION}/$(date -ud "${GATHER_EVENT_START_TIME}" +%Y/%m)`
- `EVENTS_PATH_RAW`: destination path to save events. Example: `/tmp/cci-parser/objects` (the path must exists in your filesystem)

### Extract events from CloudTrail logs


```sh
${CCI} --command extract \
    --events-path "${EVENTS_PATH_RAW}" \
    --output "${EVENTS_PATH_PARSED}" \
    --filters principal-prefix="${CLUSTER_NAME}" \
    --installer-user-name="${INSTALLER_USER_NAME}"
```

Where:

- `EVENTS_PATH_RAW`: path where the downloaded objects has been saved.
- `EVENTS_PATH_PARSED`: destination path to save the results. Example `/tmp/cci-parser/parsed` 
- `CLUSTER_NAME`: InfraId of which the cluster has been installed. You can found it on the Infrastructure object
- `INSTALLER_USER_NAME`: IAM identity used to install the cluster / call openshift-install program.

The following files will be created:

- `EVENTS_PATH_RAW/events.json`: containing the IAM identities extracted from logs, with target API calls with the number of events


### Extract insigits from identities and credentials requests

```sh
${CCI} --command compare \
	--events-path="${EVENTS_PATH_PARSED}"/events.json \
	--output="${EVENTS_PATH_PARSED}" \
	--installer-user-name="${INSTALLER_USER_NAME}" \
	--installer-user-policy="${INSTALLER_REQUEST_FILE}" \
	--filters cluster-name="${CLUSTER_NAME}" \
	${CCI_EXTRA_ARGS-}
```

Where:

- `"${EVENTS_PATH_PARSED}"/events.json`: events parsed with results by `--command extract`.
- `EVENTS_PATH_PARSED`: destination path to save the results. Example `/tmp/cci-parser/parsed` 
- `INSTALLER_USER_NAME`: IAM identity used to install the cluster / call openshift-install program.
- `INSTALLER_REQUEST_FILE`: IAM policy file exported by running `openshift-install create credentials-file`
- `CLUSTER_NAME`: InfraId used to try to discover credentials requests in Identity filess\
