fs = require 'fs'

ChromeExtension = require '../'

crx = new ChromeExtension
  crxPath: '/tmp/5d58b482687e2c2b060fc19f877425b0'
#  crxPath: 'myFirstExtension.crx'

privateKey = fs.readFileSync '/tmp/ecf3b8df877d4bea04e01393adebc369'

crx.setPrivateKey privateKey, (err) ->
  if err
    return console.log 'NOT compatible!!!'
  if !err
    console.log 'Private key compatible!!!'
  crx.unpack () ->
    #check crx.manifest, crx.path, crx.rootDirectory
    # check whether the app ID can be calculated from the "key" in the manifest.
    m = crx.manifest
    crx.manifest.name = 'Levy'
    crx.pack (err, crxFilename) =>
      console.log 'Written Filename:', crxFilename
#      debugger
#    debugger

#crx.readExtensionId (err, extensionId) ->
#  m = crx.manifest
#  debugger

#crx.unpack () ->
#  #check crx.manifest, crx.path, crx.rootDirectory
#  # check whether the app ID can be calculated from the "key" in the manifest.
#  m = crx.manifest
#  crx.manifest.name = 'Levy'
#  crx.pack (err, crxFilename) =>
#    console.log 'Written Filename:', crxFilename
#    debugger
#  debugger
