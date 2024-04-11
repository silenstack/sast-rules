import * as express from 'express';
import { exec } from 'child_process'
import * as cp from 'child_process';
const cp1 = require('child_process').exec;
const app = express()

app.get('/greeting', (req, res) => {
  const { fileName } = req.query;
  // ruleid:express-child-process
  cp1(`cat *.js ${fileName}| wc -l`)
  // ruleid:express-child-process
  exec(`cat *.js ${fileName}| wc -l`, (error, stdout, stderr) => {
    foobar()
    return res.send('ok')
  });
})

app.get('/greet-template', (req, res) => {
  // ruleid:express-child-process
  cp.spawnSync(req.body.command);
  return res.send('ok');
})

app.get('/ok-test-1', (req, res) => {
  // ok:express-child-process
  cp.spawnSync('ls');
  return res.send('ok');
})

app.get('/ok-test-2', (req, res) => {
  const foobar = smth();
  // ok:express-child-process
  exec(foobar);
  return res.send('ok');
})

app.listen(8000);
