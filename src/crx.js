var fs = require("fs")
  , path = require('path')
  , join = path.join
  , crypto = require("crypto")
  , child = require("child_process")
  , spawn = child.spawn
  , exec = child.exec,
    STATIC_HEADERS_BYTES_SIZE = 16, //a crx starts with 16 bytes that are fixed-size headers.
    PUB_KEY_LENGTH = 4,
    PUB_KEY_LENGTH_OFFSET = 8;

require('buffertools');

module.exports = new function() {
  function ChromeExtension(attrs) {
    if (this instanceof ChromeExtension) {
      for (var name in attrs) this[name] = attrs[name];

      this.path = join("/tmp", "crx-" + (Math.random() * 1e17).toString(36));
    }

    else return new ChromeExtension(attrs);
  }

  ChromeExtension.prototype = this;

  /**
   * Deletes the temp dir storing the files.
   */
  this.destroy = function() {
    spawn("rm", ["-rf", this.path]);
  };

    /**
     * Packs the directory in this.path into a CRX file, which will be put in the given filename.
     * @param callback - Will be called with (err, crxFilename)
     */
    this.pack = function (callback) {
        var that = this;
        if (typeof callback !== 'function')
            return;

        if (!this.loaded) return this.load(function (err) {
            return err ? callback(err) : that.pack(callback);
        });

        this._beforePacking(function (err) {
            if (err) return callback(err);

            that._writeCrx(callback);
        });
    };

    /**
     * Performs actions which should be performed before zipping the CRX:
     * 1. Calculates the public key if it hasn't been already calculated.
     * 2. updates the manifest.json file found in this.path.
     * @param callback - will be called with (err)
     */
    this._beforePacking = function (callback) {
        var that = this;
        this.generatePublicKey(function (err) {
            var manifest;

            if (err) return callback(err);

            manifest = JSON.stringify(this.manifest);

            that.writeFile("manifest.json", manifest, function (err) {
                if (err) return callback(err);
                //else, everything is OK
                return callback(null);
            });
        });
    };

    /**
     * Creates the CRX file from the current info, and calls the callback with the written filename
     * @param callback - Will be called with (err, crxFilename)
     */
    this._writeCrx = function (callback) {
        var pemFilename = this.path+'.pem',
            packerPath = path.resolve(__dirname+'/../pack.sh'),
            packer,
            crxFilename;

        //1. save the private key to a PEM file
        fs.writeFileSync(pemFilename, this.privateKey);

        //2. execute pack.sh with /tmp
        packer = spawn(packerPath, [this.path, pemFilename, '/tmp']);
        packer.stdout.on('data', function (filename) {
            //3. collect the written CRX filename
            crxFilename = filename.toString();
            crxFilename = crxFilename.substr(0, crxFilename.length-1); //cut the trailing '\n'
        });

        packer.on('exit', function (exitCode) {
            //4. delete the PEM file.
            spawn("rm", ["-rf", pemFilename]);

            if (typeof callback !== 'function')
                return;

            if (exitCode !== 0)
                return callback('The CRX packer exited with erroneous code: ' + exitCode);

            //5. callback with the CRX filename
            callback(null, crxFilename);
        });
    };

    /**
     * @param callback - Will be called with (err, publicKeyBytesLen).
     */
    this.readPublicKeyLength = function (fd, callback) {
        var readLength = STATIC_HEADERS_BYTES_SIZE;
        fs.read(fd, new Buffer(readLength), 0, readLength, null,
            function (err, numBytesRead, buffer) {
                var lenBuffer,
                    publicKeyBytesLen;
                if (err)
                    return callback(err);

                if (numBytesRead !== readLength)
                    return callback('Number of bytes read was ' + numBytesRead + ' but expected ' + readLength);

                lenBuffer = buffer.slice(PUB_KEY_LENGTH_OFFSET, PUB_KEY_LENGTH_OFFSET + PUB_KEY_LENGTH);
                publicKeyBytesLen = lenBuffer.readUInt8(0, 'little'); //the crx headers use little endian format
                callback(null, publicKeyBytesLen);
            });
    };

    this.readExtensionId = function (callback) {
        var that = this;
        if (typeof callback !== 'function')
            return;

        this.readPublicKeyFromFile(function (err, publicKey) {
            if (err)
                return callback(err);

            that.publicKey = publicKey;
            that.generateAppId();
            callback(null, that.appId);
        });
    };

    /**
     * Reads the public key from the header of the CRX file found in this.crx.
     * @param callback - Will be called with (err, publicKey)
     */
    this.readPublicKeyFromFile = function (callback) {
        var that = this;
        if (typeof callback !== 'function')
            return;
        if (!this.crxPath)
            return callback('no crxPath given.');

        fs.open(this.crxPath, 'r', function (err, fd) {
            that.readPublicKeyLength(fd, function (err, publicKeyBytesLen) {
                if (err) {
                    fs.close(fd); //we don't need this stream anymore
                    return callback(err);
                }

                if (publicKeyBytesLen <= 0) {
                    fs.close(fd); //we don't need this stream anymore
                    return callback('Got wrong length of public key. the value read was: ' + publicKeyBytesLen);
                }

                fs.read(fd, new Buffer(publicKeyBytesLen), 0, publicKeyBytesLen, null,
                    function (err, numBytesRead, publicKey) {
                        fs.close(fd); //we don't need this stream anymore
                        if (err)
                            return callback(err);
                        if (numBytesRead !== publicKeyBytesLen)
                            return callback('Number of bytes read was ' + numBytesRead + ' but expected ' + publicKeyBytesLen);

                        callback(null, publicKey);
                    });
            });
        });
    };

  /**
   * Extracts the .crx file located in the 'crxPath' passed in the constructor,
   * to the folder defined in this.path.
   * @param {function} callback - Will be called with (err)
   */
  this.unpack = function (callback) {
      var unzipStr = 'unzip -qd '+ this.path +' ' + this.crxPath,
          that = this;
//          unzip = spawn('unzip', ['-d', this.path, this.crxPath]);

//      exec(unzipStr, this.onLoadFinished.call(this, function () {
//          that.rootDirectory = that.path;
//          if (typeof callback === 'function')
//              callback();
//      }));

      exec(unzipStr, function (err) {
          if (err)
            return callback(err);

          that.rootDirectory = that.path;
          that.onLoadFinished(callback);
      });
  };

  /**
   * Loads manifest.json into this.manifest, and sets this.loaded to True.
   * @param callback
   */
  this.onLoadFinished = function (callback) {
      this.manifest = require(join(this.path, "manifest.json"));
      this.loaded = true;

      if (typeof callback === 'function')
          callback();
  };

    /**
     * Called from pack()
     * @param cb
     */
    this.load = function (cb) {
        var child = spawn("cp", ["-R", this.rootDirectory, this.path]);

        child.on("exit", function () {
            this.onLoadFinished(cb);
        }.bind(this));

//    child.on("exit", function() {
//      this.manifest = require(join(this.path, "manifest.json"));
//      this.loaded = true;
//
//      cb.call(this)
//    }.bind(this));
    };

  this.readFile = function(name, cb) {
    var path = join(this.path, name);

    fs.readFile(path, "binary", function(err, data) {
      if (err) return cb.call(this, err);

      cb.call(this, null, this[name] = data);
    }.bind(this));
  };

  this.writeFile = function(path, data, cb) {
    path = join(this.path, path);

    fs.writeFile(path, data, function(err, data) {
      if (err) return cb.call(this, err);

      cb.call(this);
    }.bind(this));
  };

  this.generatePublicKey = function(cb) {
    var rsa = spawn("openssl", ["rsa", "-pubout", "-outform", "DER"]);

    rsa.stdout.on("data", function(data) {
      this.publicKey = data;
      cb && cb.call(this, null, this);
    }.bind(this));

    rsa.stdin.end(this.privateKey);
  };

    /**
     * Calculates the public key derived from the given private key.
     * @param privateKey
     * @param callback - Will be called with (err, publicKey)
     */
    this.calculatePublicKeyFromPrivateKey = function (privateKey, callback) {
        var rsa;
        if (typeof callback !== 'function')
            return;

        rsa = spawn("openssl", ["rsa", "-pubout", "-outform", "DER"]);

        rsa.stdout.on("data", function(publicKey) {
          callback(null, publicKey);
        });

        rsa.stdin.end(privateKey);
    };

    /**
     * Called from this.pack()
     * @return {*}
     */
    this.generateSignature = function() {
        var signatureStr = crypto.createSign("sha1").update(this.contents).sign(this.privateKey);
        return this.signature = new Buffer(signatureStr, "binary");
    };

    /**
     * Sets this.privateKey to be the given private key, if the given key is indeed the one that was used
     * to create the CRX in this.crxPath.
     * @param privateKey
     * @param callback - Will be called with (err)
     */
    this.setPrivateKey = function (privateKey, callback) {
        var that = this;
        if (typeof callback !== 'function')
            return;
        if (!this.crxPath)
            return callback('no crxPath given.');

        this.verifyPrivateKeyBelongsToCrx(privateKey, function (err, belongs) {
            if (err)
                return callback(err);
            if (!belongs)
                return callback('The given private key does not belong to the crx in the crxPath that was set.');
            //else, the private key belongs to the CRX and everything is OK.
            that.privateKey = privateKey;
            callback(null);
        });
    };

    /**
     * Compares the public key read from the header of this.crxPath
     * to the one calculated from the given private key.
     * @param privateKey
     * @param callback - Will be called with (err, belongs)
     */
    this.verifyPrivateKeyBelongsToCrx = function (privateKey, callback) {
        var that = this;
        if (typeof callback !== 'function')
            return;

        this.calculatePublicKeyFromPrivateKey(privateKey, function (err, publicKeyFromPrivateKey) {
            if (err)
                return callback(err);
            that.readPublicKeyFromFile(function (err, publicKeyReadFromFile) {
                var privateKeyBelongsToCrx;
                if (err)
                    return callback(err);

                //now determine if the two public keys are the same
                privateKeyBelongsToCrx = publicKeyReadFromFile.compare(publicKeyFromPrivateKey) == 0;
                callback(null, privateKeyBelongsToCrx);
            });
        });
    };

  /**
   * Zips the contents of the folder of this.path.
   * @param cb - Callback
   */
  this.loadContents = function(cb) {
    var command = "zip -qr -9 -X - . -x key.pem",
        options = {cwd: this.path, encoding: "binary", maxBuffer: this.maxBuffer};

    exec(command, options, function(err, data) {
      if (err) return cb.call(this, err);

      this.contents = new Buffer(data, "binary");

      cb.call(this);
    }.bind(this));
  };
  
  this.generatePackage = function() {
    var signature = this.signature
      , publicKey = this.publicKey
      , contents  = this.contents

      , keyLength = publicKey.length
      , sigLength = signature.length
      , zipLength = contents.length
      , length = 16 + keyLength + sigLength + zipLength

      , crx = new Buffer(length);

    crx.write("Cr24" + Array(13).join("\x00"), "binary");

    crx[4] = 2;
    crx[8] = keyLength;
    crx[12] = sigLength;

    publicKey.copy(crx, 16);
    signature.copy(crx, 16 + keyLength);
    contents.copy(crx, 16 + keyLength + sigLength);

    return this.package = crx;
  };

  this.generateAppId = function() {
    return this.appId = crypto
      .createHash("sha256")
      .update(this.publicKey)
      .digest("hex")
      .slice(0, 32)
      .replace(/./g, function(x) {
        return (parseInt(x, 16) + 10).toString(26);
      });
  };

  this.generateUpdateXML = function() {
    if (!this.codebase) throw new Error("No URL provided for update.xml.");

    return this.updateXML =
      new Buffer(
        "<?xml version='1.0' encoding='UTF-8'?>\n" +
        "<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>\n" +
        "  <app appid='" + this.generateAppId() + "'>\n" +
        "    <updatecheck codebase='" + this.codebase + "' version='" + this.manifest.version + "' />\n" +
        "  </app>\n" +
        "</gupdate>"
      );
  };

  return ChromeExtension;
};