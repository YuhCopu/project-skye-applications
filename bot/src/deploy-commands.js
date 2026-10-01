import 'dotenv/config';
import { REST, Routes, SlashCommandBuilder, ChannelType, PermissionFlagsBits } from 'discord.js';

const commands = [
  new SlashCommandBuilder().setName('skye-panel').setDescription('Post the Skye Applications panel.'),
  new SlashCommandBuilder().setName('skye-config').setDescription('Configure Skye application channels and review permissions.')
    .addChannelOption(o=>o.setName('support_channel').setDescription('Support submission channel').addChannelTypes(ChannelType.GuildText))
    .addChannelOption(o=>o.setName('creator_channel').setDescription('Creator submission channel').addChannelTypes(ChannelType.GuildText))
    .addChannelOption(o=>o.setName('staff_channel').setDescription('Staff submission channel').addChannelTypes(ChannelType.GuildText))
    .addChannelOption(o=>o.setName('partnership_channel').setDescription('Partnership submission channel').addChannelTypes(ChannelType.GuildText))
    .addRoleOption(o=>o.setName('review_role').setDescription('Role allowed to review applications')),
  new SlashCommandBuilder().setName('skye-stats').setDescription('Show application statistics.'),
  new SlashCommandBuilder().setName('skye-search').setDescription('Search stored Skye applications.')
    .addStringOption(o=>o.setName('query').setDescription('ID, username, user ID, or application type').setRequired(true))
    .addStringOption(o=>o.setName('status').setDescription('Filter by status').addChoices({name:'Pending',value:'Pending'},{name:'Accepted',value:'Accepted'},{name:'Denied',value:'Denied'},{name:'Changes Requested',value:'Changes Requested'})),
  new SlashCommandBuilder().setName('skye-applicant').setDescription('Show applications from a Discord user.')
    .addUserOption(o=>o.setName('user').setDescription('Applicant').setRequired(true)),
  new SlashCommandBuilder().setName('skye-trust').setDescription('Grant a Discord user access to the Skye dashboard.').addUserOption(o=>o.setName('user').setDescription('Trusted dashboard user').setRequired(true)),
  new SlashCommandBuilder().setName('skye-untrust').setDescription('Remove a Discord user from the Skye dashboard.').addUserOption(o=>o.setName('user').setDescription('Dashboard user').setRequired(true)),
  new SlashCommandBuilder().setName('skye-help').setDescription('Show Skye Applications commands.')
].map(c=>c.setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild).toJSON());

const rest=new REST({version:'10'}).setToken(process.env.DISCORD_TOKEN);
const route=process.env.GUILD_ID?Routes.applicationGuildCommands(process.env.CLIENT_ID,process.env.GUILD_ID):Routes.applicationCommands(process.env.CLIENT_ID);
await rest.put(route,{body:commands});
console.log(`Registered ${commands.length} Skye commands.`);
