#!/usr/bin/env node
/**
 * Start All Services
 * 
 * Starts all Sentinel services with a single command:
 * - Frontend (Console)
 * - Query API
 * - Threat Model API (Python)
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  blue: '\x1b[34m',
};

function log(service, message, color = 'cyan') {
  const timestamp = new Date().toLocaleTimeString();
  const prefix = `${colors[color]}[${service}]${colors.reset}`;
  console.log(`${prefix} ${message}`);
}

function checkNmap() {
  try {
    require('child_process').execSync('nmap --version', { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}


function checkPython() {
  try {
    const version = require('child_process').execSync('python --version', { encoding: 'utf-8' });
    return version.includes('Python 3');
  } catch {
    try {
      const version = require('child_process').execSync('python3 --version', { encoding: 'utf-8' });
      return version.includes('Python 3');
    } catch {
      return false;
    }
  }
}

function checkThreatModelSetup() {
  const modelsPath = path.join(__dirname, 'models copy');
  const requiredFiles = ['vectorizer.pkl', 'cwe_model.pkl', 'cwe_binarizer.pkl', 'capec_model.pkl', 'capec_binarizer.pkl'];
  
  if (!fs.existsSync(modelsPath)) {
    return { exists: false, missing: ['models copy directory'] };
  }
  
  const missing = requiredFiles.filter(file => {
    const filePath = path.join(modelsPath, file);
    return !fs.existsSync(filePath);
  });
  
  return { exists: missing.length === 0, missing };
}

async function startService(name, command, args, cwd, env = {}) {
  return new Promise((resolve, reject) => {
    log(name, `Starting...`, 'cyan');
    
    const proc = spawn(command, args, {
      cwd,
      shell: true,
      stdio: 'pipe',
      env: { ...process.env, ...env },
    });

    proc.stdout.on('data', (data) => {
      const lines = data.toString().split('\n').filter(l => l.trim());
      lines.forEach(line => {
        if (line.includes('error') || line.includes('Error') || line.includes('ERROR')) {
          log(name, line, 'red');
        } else if (line.includes('running') || line.includes('listening') || line.includes('Uvicorn')) {
          log(name, line, 'green');
        } else {
          log(name, line, 'cyan');
        }
      });
    });

    proc.stderr.on('data', (data) => {
      const lines = data.toString().split('\n').filter(l => l.trim());
      lines.forEach(line => {
        if (!line.includes('WARNING') && !line.includes('DeprecationWarning')) {
          log(name, line, 'yellow');
        }
      });
    });

    proc.on('error', (err) => {
      log(name, `Failed to start: ${err.message}`, 'red');
      reject(err);
    });

    proc.on('exit', (code) => {
      if (code !== 0 && code !== null) {
        log(name, `Exited with code ${code}`, 'red');
      }
    });

    // Give it a moment to start
    setTimeout(() => {
      resolve(proc);
    }, 1000);
  });
}

async function main() {
  console.log(`${colors.bright}${colors.cyan}`);
  console.log('╔════════════════════════════════════════╗');
  console.log('║   🚀 Sentinel - Starting All Services ║');
  console.log('╚════════════════════════════════════════╝');
  console.log(`${colors.reset}\n`);

  // Check prerequisites
  log('CHECK', 'Checking prerequisites...', 'blue');
  
  const hasNmap = checkNmap();
  if (!hasNmap) {
    log('CHECK', '⚠️  nmap not found (optional - needed for network scanning)', 'yellow');
  } else {
    log('CHECK', '✅ nmap found', 'green');
  }

  const hasPython = checkPython();
  if (!hasPython) {
    log('CHECK', '⚠️  Python 3 not found (optional - needed for threat model API)', 'yellow');
  } else {
    log('CHECK', '✅ Python 3 found', 'green');
  }

  const threatModelCheck = checkThreatModelSetup();
  if (!threatModelCheck.exists) {
    log('CHECK', `⚠️  Threat models missing: ${threatModelCheck.missing.join(', ')}`, 'yellow');
    log('CHECK', '   Threat Model API will not start', 'yellow');
  } else {
    log('CHECK', '✅ Threat models found', 'green');
  }

  console.log('');

  const processes = [];

  // Start Query API
  try {
    log('QUERY', 'Starting Query API on port 8000...', 'cyan');
    const queryProc = await startService(
      'QUERY',
      'npm',
      ['run', 'dev'],
      path.join(__dirname, 'apps', 'query'),
      { NODE_OPTIONS: '--max-old-space-size=4096', ...process.env }
    );
    processes.push({ name: 'Query API', proc: queryProc });
  } catch (err) {
    log('QUERY', 'Failed to start (may need database connection)', 'yellow');
  }

  // Start Threat Model API (if Python and models available)
  if (hasPython && threatModelCheck.exists) {
    try {
      log('THREAT', 'Starting Threat Model API on port 8001...', 'cyan');
      const threatModelPath = path.join(__dirname, 'services', 'threat-model');
      const venvPath = path.join(threatModelPath, '.venv');
      
      let pythonCmd;
      let uvicornArgs;
      
      if (fs.existsSync(venvPath)) {
        // Use venv Python if it exists
        if (process.platform === 'win32') {
          pythonCmd = path.join(venvPath, 'Scripts', 'python.exe');
        } else {
          pythonCmd = path.join(venvPath, 'bin', 'python');
        }
        
        // Verify venv Python works
        try {
          require('child_process').execSync(`"${pythonCmd}" --version`, { stdio: 'ignore' });
        } catch {
          log('THREAT', '⚠️  Virtual environment Python not working, trying system Python...', 'yellow');
          // Fallback to system Python
          try {
            require('child_process').execSync('python --version', { stdio: 'ignore' });
            pythonCmd = 'python';
          } catch {
            pythonCmd = 'python3';
          }
        }
        
        uvicornArgs = ['-m', 'uvicorn', 'main:app', '--host', '0.0.0.0', '--port', '8001'];
      } else {
        // Try to find Python 3.11 specifically (required for scipy compatibility)
        let foundPython = false;
        const pythonVersions = ['py -3.11', 'python3.11', 'python'];
        
        for (const pyCmd of pythonVersions) {
          try {
            const version = require('child_process').execSync(`${pyCmd} --version`, { encoding: 'utf-8' });
            if (version.includes('Python 3.11') || version.includes('Python 3.10')) {
              pythonCmd = pyCmd.split(' ')[0]; // Get just the command name
              foundPython = true;
              break;
            }
          } catch {
            continue;
          }
        }
        
        if (!foundPython) {
          // Fallback to system Python
          try {
            require('child_process').execSync('python --version', { stdio: 'ignore' });
            pythonCmd = 'python';
          } catch {
            pythonCmd = 'python3';
          }
        }
        
        uvicornArgs = ['-m', 'uvicorn', 'main:app', '--host', '0.0.0.0', '--port', '8001'];
      }

      const threatProc = await startService(
        'THREAT',
        pythonCmd,
        uvicornArgs,
        threatModelPath
      );
      processes.push({ name: 'Threat Model API', proc: threatProc });
    } catch (err) {
      log('THREAT', 'Failed to start (check Python setup)', 'yellow');
    }
  } else {
    log('THREAT', 'Skipping (Python or models not available)', 'yellow');
  }

  // Start Frontend
  try {
    log('CONSOLE', 'Starting Frontend on port 3000...', 'cyan');
    const consoleProc = await startService(
      'CONSOLE',
      'npm',
      ['run', 'dev'],
      path.join(__dirname, 'apps', 'console')
    );
    processes.push({ name: 'Console', proc: consoleProc });
  } catch (err) {
    log('CONSOLE', 'Failed to start', 'red');
  }

  // Wait a bit for services to start
  await new Promise(resolve => setTimeout(resolve, 3000));

  console.log(`\n${colors.bright}${colors.green}`);
  console.log('╔════════════════════════════════════════╗');
  console.log('║   ✅ All Services Started!              ║');
  console.log('╚════════════════════════════════════════╝');
  console.log(`${colors.reset}`);
  console.log(`${colors.cyan}📊 Services:${colors.reset}`);
  console.log(`   ${colors.green}Frontend:${colors.reset}     http://localhost:3000`);
  console.log(`   ${colors.green}Query API:${colors.reset}    http://localhost:8000`);
  if (hasPython && threatModelCheck.exists) {
    console.log(`   ${colors.green}Threat API:${colors.reset}    http://localhost:8001`);
  }
  console.log(`\n${colors.yellow}Press Ctrl+C to stop all services${colors.reset}\n`);

  // Handle shutdown
  process.on('SIGINT', () => {
    console.log(`\n${colors.yellow}Shutting down services...${colors.reset}`);
    processes.forEach(({ name, proc }) => {
      try {
        proc.kill();
        log(name, 'Stopped', 'yellow');
      } catch (err) {
        // Ignore
      }
    });
    process.exit(0);
  });

  // Keep process alive
  await new Promise(() => {});
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});

