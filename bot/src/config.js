import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.resolve(here, '../data');
fs.mkdirSync(dataDir, { recursive: true });
const configFile = path.join(dataDir, 'config.json');
const submissionsFile = path.join(dataDir, 'submissions.json');
const counterFile = path.join(dataDir, 'counter.json');

const questions = {
  support: [
    'What is your Discord username?', 'How old are you?', 'Why do you want to become Support?',
    'No Audio Issue: What steps would you take to troubleshoot it?', 'Application Crash Detected Error: What steps would you take?',
    'What would you do if the login screen does not work?', 'How would you handle a Failed Descriptor File error?',
    'Network Error Issue: What would you check first?', 'How active are you from 1–10?'
  ],
  creator: [
    'What is your creator name?', 'What platforms do you create on?', 'Send your main social/profile link.',
    'How many followers/subscribers do you have?', 'What type of content do you make?', 'How often do you upload?',
    'Why do you want to create content for Skye?', 'What value would you bring to the community?',
    'Link an example of your content.', 'Anything else you want us to know?'
  ],
  staff: [
    'What is your Discord username?', 'How old are you?', 'Why do you want to join the Skye staff team?',
    'What relevant experience do you have?', 'How would you handle a difficult member?', 'How active can you be each week?'
  ],
  partnership: [
    'What is your Discord username?', 'What is your community/server called?', 'Send your server invite.',
    'How many members are in your community?', 'What type of community is it?', 'What are you looking for from Skye?',
    'What can you offer Skye?', 'Why should we partner?', 'Anything else you want us to know?'
  ]
};

export const defaults = {
  brand: { name: 'Skye Applications', accent: 0x8FA7FF },
  panel: {
    title: '☁️ Skye Applications',
    description: 'Want to become part of Skye?\nChoose an application below and complete the questions privately in your DMs.',
    footer: 'Skye Applications',
  },
  reviewRoleId: '',
  trustedUserIds: [],
  channels: { support: '', creator: '', staff: '', partnership: '' },
  messages: {
    started: '☁️ **Your {type} application has started.**\n\nI’ll ask every question here in DMs. Reply to each question in order.\n\nType `cancel` at any time to stop.',
    questionPrefix: '**Question {current}/{total}**\n{question}',
    submitted: '✅ **Application submitted!**\nYour application ID is `{id}`. Staff will review it soon.',
    accepted: '🎉 **Application accepted!**\nYour application `{id}` was accepted by the Skye team.{reason}',
    denied: 'Thanks for applying. Your application `{id}` was denied by the Skye team.{reason}',
    changes: '📝 **Changes requested for `{id}`**\nA reviewer has asked you to review your application.{reason}'
  },
  applicationTypes: [
    { id:'support', name:'Support', emoji:'🛠️', description:'Help members solve issues and questions.', active:true, questions:questions.support, roles:{onSubmit:[],onAccept:[],onDeny:[],removeOnAccept:[],removeOnDeny:[]} },
    { id:'creator', name:'Content Creator', emoji:'🎥', description:'Create content and help grow the Skye community.', active:true, questions:questions.creator, roles:{onSubmit:[],onAccept:[],onDeny:[],removeOnAccept:[],removeOnDeny:[]} },
    { id:'staff', name:'Staff', emoji:'🛡️', description:'Help manage, moderate, and improve the community.', active:true, questions:questions.staff, roles:{onSubmit:[],onAccept:[],onDeny:[],removeOnAccept:[],removeOnDeny:[]} },
    { id:'partnership', name:'Partnership', emoji:'🤝', description:'Work with Skye on community partnerships.', active:true, questions:questions.partnership, roles:{onSubmit:[],onAccept:[],onDeny:[],removeOnAccept:[],removeOnDeny:[]} }
  ]
};

function merge(base, incoming) {
  if (!incoming || typeof incoming !== 'object') return base;
  for (const [key, value] of Object.entries(incoming)) {
    if (value && typeof value === 'object' && !Array.isArray(value) && base[key] && typeof base[key] === 'object' && !Array.isArray(base[key])) merge(base[key], value);
    else base[key] = value;
  }
  return base;
}
export function load() {
  let cfg = structuredClone(defaults);
  if (fs.existsSync(configFile)) { try { cfg = merge(cfg, JSON.parse(fs.readFileSync(configFile,'utf8'))); } catch {} }
  return cfg;
}
export function save(cfg) { fs.writeFileSync(configFile, JSON.stringify(cfg, null, 2)); }
export function allSubmissions() { if (!fs.existsSync(submissionsFile)) return []; try { return JSON.parse(fs.readFileSync(submissionsFile,'utf8')); } catch { return []; } }
export function addSubmission(record) { const all=allSubmissions(); all.push(record); fs.writeFileSync(submissionsFile, JSON.stringify(all,null,2)); return record; }
export function updateSubmission(id, patch) { const all=allSubmissions(); const i=all.findIndex(x=>x.id===id); if(i<0)return null; all[i]={...all[i],...patch}; fs.writeFileSync(submissionsFile, JSON.stringify(all,null,2)); return all[i]; }
export function nextId() { let n=1; if(fs.existsSync(counterFile)){try{n=Number(JSON.parse(fs.readFileSync(counterFile,'utf8')).value)||1}catch{}} fs.writeFileSync(counterFile, JSON.stringify({value:n+1})); return `SKYE-${String(n).padStart(6,'0')}`; }
