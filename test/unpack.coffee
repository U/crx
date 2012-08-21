fs = require 'fs'

ChromeExtension = require '../'

crx = new ChromeExtension
  crxPath: '/tmp/80cd8b804796ba0307a041d7e18810b8'
#  crxPath: 'myFirstExtension.crx'

crx.readExtensionId (err, extensionId) ->
  m = crx.manifest
  debugger

crx.unpack () ->
  #check crx.manifest, crx.path, crx.rootDirectory
  # check whether the app ID can be calculated from the "key" in the manifest.
  m = crx.manifest
  debugger
