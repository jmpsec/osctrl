#!/usr/bin/env bash
#
# Helper to release osctrl versions

if [ $# -ne 1 ] ; then
  echo "Usage: $0 <version_to_add>"
  exit 1
fi

TAG=$1
if [[ ${TAG:0:1} != 'v' ]]; then
  TAG="v$1"
fi

BODY="Release $TAG"
BRANCH=$(git rev-parse --abbrev-ref HEAD)
REPO=$(git config --get remote.origin.url | sed 's/.*:\/\/github.com\///;s/.git$//')

generate_post_data()
{
  cat <<EOF
{
  "tag_name": "$TAG",
  "target_commitish": "$BRANCH",
  "name": "$TAG",
  "body": "$BODY",
  "draft": false,
  "prerelease": false
}
EOF
}

echo "[+] Create release $TAG for repo: $REPO branch: $BRANCH"
echo

read -p " -> Github token? " TOKEN

echo "[+] Sending POST request to Github API"
echo

curl --data "$(generate_post_data)" "https://api.github.com/repos/$REPO/releases?access_token=$TOKEN"

echo "[+] Done"
