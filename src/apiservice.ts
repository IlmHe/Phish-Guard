import { createClient } from '@supabase/supabase-js';

export async function checkUrlInSupabase(url: string): Promise<boolean> {
  const supabaseUrl = process.env.SUPABASE_URL as string;
  const supabaseKey = process.env.SUPABASE_KEY as string;
  const supabase = createClient(supabaseUrl, supabaseKey);

  const { data, error } = await supabase
    .from('phish-co-za_urls')
    .select('url')
    .eq('url', url);

  if (error) {
    console.error('Error querying Supabase:', error);
    throw new Error('Failed to query Supabase');
  }

  return data.length > 0;
}
