import { Scalekit } from '@scalekit-sdk/node';

const requiredEnvVars = [
  'SCALEKIT_ENVIRONMENT_URL',
  'SCALEKIT_CLIENT_ID',
  'SCALEKIT_CLIENT_SECRET',
];

export function validateEnvironmentVariables() {
  const missingEnvVars = requiredEnvVars.filter(
    (varName) => !process.env[varName]
  );

  if (missingEnvVars.length > 0) {
    console.error('\n❌ Missing required environment variables:');
    missingEnvVars.forEach((varName) => {
      console.error(`   - ${varName}`);
    });
    console.error('\nPlease create a .env file with the following variables:');
    console.error('SCALEKIT_ENVIRONMENT_URL=your_environment_url');
    console.error('SCALEKIT_CLIENT_ID=your_client_id');
    console.error('SCALEKIT_CLIENT_SECRET=your_client_secret');
    console.error('\nYou can get these values from your Scalekit dashboard.\n');
    process.exit(1);
  }

  // Validate environment URL format
  const envUrl = process.env.SCALEKIT_ENVIRONMENT_URL;
  if (!envUrl.startsWith('https://')) {
    console.error('\n❌ Invalid SCALEKIT_ENVIRONMENT_URL:');
    console.error('   The environment URL must start with https://');
    console.error(`   Current value: ${envUrl}`);
    process.exit(1);
  }

  // Validate client ID format (should start with 'skc_')
  const clientId = process.env.SCALEKIT_CLIENT_ID;
  if (!clientId.startsWith('skc_')) {
    console.error('\n❌ Invalid SCALEKIT_CLIENT_ID format:');
    console.error('   Client ID should start with "skc_"');
    console.error(`   Current value: ${clientId}`);
    console.error(
      '\nPlease check your Scalekit dashboard for the correct client ID.\n'
    );
    process.exit(1);
  }

  // Validate client secret format (should start with 'test_' or 'live_')
  const clientSecret = process.env.SCALEKIT_CLIENT_SECRET;
  if (!clientSecret.startsWith('test_') && !clientSecret.startsWith('live_')) {
    console.error('\n❌ Invalid SCALEKIT_CLIENT_SECRET format:');
    console.error('   Client secret should start with "test_" or "live_"');
    console.error(`   Current value: ${clientSecret.substring(0, 10)}...`);
    console.error(
      '\nPlease check your Scalekit dashboard for the correct client secret.\n'
    );
    process.exit(1);
  }

  try {
    let scalekit = new Scalekit(
      process.env.SCALEKIT_ENVIRONMENT_URL,
      process.env.SCALEKIT_CLIENT_ID,
      process.env.SCALEKIT_CLIENT_SECRET
    );

    console.info('✅ Environment variables validated successfully');
    console.info(`   Environment: ${envUrl}`);
    console.info(`   Client ID: ${clientId.substring(0, 10)}...`);
    console.info(`   Client Secret: ${clientSecret.substring(0, 10)}...`);

    return scalekit;
  } catch (error) {
    console.error('\n❌ Error initializing ScaleKit:', error.message);
    console.error('\nPlease check:');
    console.error('1. Your SCALEKIT_ENVIRONMENT_URL is correct');
    console.error(
      '2. Your SCALEKIT_CLIENT_ID and SCALEKIT_CLIENT_SECRET match your Scalekit dashboard'
    );
    console.error('3. Your Scalekit application is properly configured');
    console.error('\nFor help, visit: https://docs.scalekit.com\n');
    process.exit(1);
  }
}
