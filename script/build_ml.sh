#!/bin/bash

echo "Building for: $TRAVIS_OS_NAME"
echo "CWD: $PWD"
echo "Node $(node --version)"
echo "NPM $(npm --version)"

# make for production
unset TEST_RUN
export NODE_ENV=production
npm install electron-builder@next -g
npm install --production
npm prune

if [ "$TRAVIS_OS_NAME" == "linux" ]; then
  # to build for linux
  sudo apt-get install --no-install-recommends -y icnsutils graphicsmagick xz-utils
  echo "Building for linux"
  npm run linbuild
else
  echo "Building for mac"
  npm run macbuild
fi
# zip -r dist/**/*.zip ./github/RELEASE
