#!/bin/bash -x

source ${OKTA_HOME}/${REPO}/scripts/setup-e2e.sh

if [ ! -z "$AUTHJS_VERSION" ]; then
  echo "Skipping e2e tests against auth-js v6.x"
  exit ${SUCCESS}
fi

setup_service java 1.8.222
setup_service google-chrome-stable 121.0.6167.85-1

export AUTHJS_VERSION_6="true"
export TEST_SUITE_TYPE="junit"
export TEST_RESULT_FILE_DIR="${REPO}/test-reports/e2e"

export ISSUER=https://samples-javascript.okta.com/oauth2/default
export SPA_CLIENT_ID=0oapmwm72082GXal14x6
export USERNAME=george@acme.com
get_terminus_secret "/" PASSWORD PASSWORD

export CI=true
export DBUS_SESSION_BUS_ADDRESS=/dev/null

if ! yarn add -DW --ignore-scripts @okta/okta-auth-js@^6; then
  echo "auth-js v6.x could not be installed"
  exit ${FAILED_SETUP}
fi

# Install dependencies for test apps
for app in test/apps/angular-*
do
  pushd $app
    if ! yarn add --ignore-scripts @okta/okta-auth-js@^6; then
      echo "auth-js v6.x could be installed in test app ${app}"
      exit ${FAILED_SETUP}
    fi
  popd
done

if [ -z "${PASSWORD}" ]; then
  echo "No PASSWORD has been set! Exiting..."
  exit ${TEST_FAILURE}
fi

if ! yarn test:e2e; then
  echo "unit failed! Exiting..."
  exit ${TEST_FAILURE}
fi

echo ${TEST_SUITE_TYPE} > ${TEST_SUITE_TYPE_FILE}
echo ${TEST_RESULT_FILE_DIR} > ${TEST_RESULT_FILE_DIR_FILE}
exit ${PUBLISH_TYPE_AND_RESULT_DIR}
