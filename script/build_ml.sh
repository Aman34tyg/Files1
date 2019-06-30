#!/bin/bash

echo "Building for: $TRAVIS_OS_NAME"
echo "CWD: $PWD"

# make for production
unset TEST_RUN
export NODE_ENV=production
npm install --production
npm prune
npm install electron-builder@next -g

if [ "$TRAVIS_OS_NAME" == "linux" ]; then
  # to build for linux
  sudo apt-get install --no-install-recommends -y icnsutils graphicsmagick xz-utils
  npm run linbuild
else
  npm run macbuild
fi
# zip -r dist/**/*.zip ./github/RELEASE
