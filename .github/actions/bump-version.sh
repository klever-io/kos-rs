#!/bin/bash
#get highest tag number, and add 0.1.0 if doesn't exist
CURRENT_VERSION=$(git describe --abbrev=0 --tags 2>/dev/null || true)
if [[ $CURRENT_VERSION == '' ]]
then
CURRENT_VERSION='v0.1.0'
fi
echo "Current Version: $CURRENT_VERSION"

#replace . with space so can split into an array
CURRENT_VERSION_PARTS=(${CURRENT_VERSION//./ })

#get number parts
VNUM1=${CURRENT_VERSION_PARTS[0]}
VNUM2=${CURRENT_VERSION_PARTS[1]}
VNUM3=${CURRENT_VERSION_PARTS[2]}

VERSION=$1

if [[ $VERSION == 'major' ]]
then
VNUM1=$((VNUM1+1))
elif [[ $VERSION == 'minor' ]]
then
VNUM2=$((VNUM2+1))
elif [[ $VERSION == 'patch' ]]
then
VNUM3=$((VNUM3+1))
else
echo "No version type or incorrect type specified"
exit 1
fi

#create new tag
release_tag="$VNUM1.$VNUM2.$VNUM3"
cargo_release_tag="${release_tag:1}"          
echo "($VERSION) updating $CURRENT_VERSION to $release_tag, Cargo.toml to $cargo_release_tag"

# change version in Cargo.toml
eval "sed -i '23s/.*/version = \"${cargo_release_tag}\"/' Cargo.toml"

git config --global user.email "devsecops@klever.io"
git config --global user.name "DevSecOps"         
git add Cargo.toml
git commit -m "Bump Version $release_tag" || exit 0

#git remote set-url origin https://x-access-token:${{ secrets.GITHUB_TOKEN }}@github.com/${{ github.repository }}
# push changes
git push
# create tag
git tag -a $release_tag -m "Release $release_tag"
git push origin $release_tag
