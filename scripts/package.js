#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const archiver = require('archiver');

const browser = process.argv[2];
const sourceDir = process.argv[3];
const outputFile = process.argv[4];

if (!browser || !sourceDir || !outputFile) {
  console.error('Usage: node package.js <browser> <sourceDir> <outputFile>');
  process.exit(1);
}

// Create a file to stream archive data to
const output = fs.createWriteStream(outputFile);
const archive = archiver('zip', {
  zlib: { level: 9 } // Best compression
});

// Listen for all archive data to be written
output.on('close', function() {
  console.log(`✓ ${browser} package created: ${outputFile} (${archive.pointer()} bytes)`);
});

// Good practice to catch warnings (ie stat failures and other non-blocking errors)
archive.on('warning', function(err) {
  if (err.code === 'ENOENT') {
    console.warn(err);
  } else {
    throw err;
  }
});

// Good practice to catch this error explicitly
archive.on('error', function(err) {
  throw err;
});

// Pipe archive data to the file
archive.pipe(output);

// Append files from a sub-directory, putting its contents at the root of archive
archive.directory(sourceDir, false);

// Finalize the archive (ie we are done appending files but streams have to finish yet)
archive.finalize();