const { app, ipcMain, Menu, BrowserWindow } = require('electron')
const { VIEWS, ERRORS, WINDOW_OPTS } = require('../config')
const crypto = require('../core/crypto')
const menuTemplate = require('./menu')
const { isCryptoFile } = require('../utils/utils')
const logger = require('../utils/logger')

exports.window = function (global, fileToCrypt, callback) {
  // creates a new BrowserWindow
  let win = new BrowserWindow({
    width: 350,
    height: 460,
    ...WINDOW_OPTS
  })
  // create menu from menuTemplate
  const menu = Menu.buildFromTemplate(menuTemplate)
  // set menu
  Menu.setApplicationMenu(menu)
  // loads crypt.html view into the BrowserWindow
  win.loadURL(VIEWS.CRYPTER)

  let webContents = win.webContents

  webContents.once('dom-ready', () => {
    // Process any file opened with app before this window
    if (fileToCrypt) {
      logger.info('Got a file to crypt', fileToCrypt)
      cryptFile(fileToCrypt)
    }
  })


  function encrypt(filePath) {
    // Update UI
    webContents.send('encryptingFile', filePath)
    crypto.crypt(filePath, global.MasterPassKey.get())
      .then((file) => {
        webContents.send('cryptedFile', file)
      })
      .catch((err) => {
        logger.info(`cryptFile error`)
        logger.error(err)
        webContents.send('cryptErr', err.message)
      })
  }

  function decrypt(filePath) {
    // Update UI
    webContents.send('decryptingFile', filePath)
    crypto.decrypt(filePath, global.MasterPassKey.get())
      .then((file) => {
        logger.info('decrypted')
        webContents.send('decryptedFile', file)
      })
      .catch((err) => {
        logger.info(`decryptFile error`)
        logger.error(err)
        switch (err.message.trim()) {
        case ERRORS.MS.INVALID_FILE:
          webContents.send('cryptErr', ERRORS.INVALID_FILE)
          break;
        case ERRORS.MS.AUTH_FAIL:
          webContents.send('cryptErr', ERRORS.AUTH_FAIL)
          break;
        default:
          webContents.send('cryptErr', err.message)
        }
      })
  }

  function cryptFile(file) {
    if (isCryptoFile(file)) {
      decrypt(file)
    } else {
      encrypt(file)
    }
  }

  ipcMain.on('app:open-settings', (event) => {
    logger.verbose('CRYPTER: app:open-settings emitted.')
    app.emit('app:open-settings')
  })

  // Process any file opened with app while this window is active
  ipcMain.on('cryptFile', (event, file) => cryptFile(file))
  // app.on('cryptFile', (event, file) => logger.info(file))

  win.on('closed', function () {
    logger.info('win.closed event emitted for PromptWindow')
    win = null
    callback()
  })

  return win
}