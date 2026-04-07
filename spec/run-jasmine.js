const Jasmine = require('jasmine');
const JasmineReporters = require('jasmine-reporters');
const fs = require('fs');

const jasmine = new Jasmine();

// Load the configuration
jasmine.loadConfigFile('spec/support/jasmine.json');  // Make sure this path is correct

// Configure the JUnit XML Reporter
const junitReporter = new JasmineReporters.JUnitXmlReporter({
    savePath: './test-results', // Directory to save the report
    consolidate: true, // Consolidate all results into a single file
});

// Add the reporter to Jasmine
jasmine.env.addReporter(junitReporter);

// Execute Jasmine
jasmine.exitOnCompletion = false;
jasmine.execute()
    .then(function(result) {
        console.log('Tests completed. Overall status:', result.overallStatus);
        process.exitCode = 0;
    })
    .catch(function(error) {
        console.error('An unexpected error occurred:', error);
        process.exitCode = 1;
    });