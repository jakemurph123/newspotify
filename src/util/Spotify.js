const clientId = 'c5f4c6e4d986474081c716224f9930c6';
const redirectUri = 'https://jakemurph123.github.io/newspotify/';
const tokenEndpoint = 'https://accounts.spotify.com/api/token';
let accessToken;

function generateRandomString(length) {
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from(crypto.getRandomValues(new Uint8Array(length)))
    .map(x => possible.charAt(x % possible.length))
    .join('');
}

async function generateCodeChallenge(codeVerifier) {
  const data = new TextEncoder().encode(codeVerifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

const Spotify = {
  async getAccessToken() {
    if (accessToken) return accessToken;

    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");

    if (!code) {
      // Step 1: Begin auth flow
      const codeVerifier = generateRandomString(128);
      const codeChallenge = await generateCodeChallenge(codeVerifier);
      localStorage.setItem("spotify_code_verifier", codeVerifier);

      const authUrl = `https://accounts.spotify.com/authorize?client_id=${clientId}&response_type=code&redirect_uri=${redirectUri}&scope=playlist-modify-public&code_challenge_method=S256&code_challenge=${codeChallenge}`;
      window.location = authUrl;
      return;
    } else {
      // Step 2: Exchange code for token
      const codeVerifier = localStorage.getItem("spotify_code_verifier");

      const body = new URLSearchParams({
        grant_type: "authorization_code",
        code: code,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: codeVerifier
      });

      const response = await fetch(tokenEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: body
      });

      const data = await response.json();
      accessToken = data.access_token;
      window.history.replaceState({}, document.title, "/newspotify/"); // Clean up URL
      return accessToken;
    }
  },

  async search(term) {
    const token = await this.getAccessToken();
    if (!token) return [];

    return fetch(`https://api.spotify.com/v1/search?type=track&q=${term}`, {
      headers: {
        Authorization: `Bearer ${token}`
      }
    })
    .then(res => res.json())
    .then(json => {
      if (!json.tracks) return [];
      return json.tracks.items.map(track => ({
        id: track.id,
        name: track.name,
        artist: track.artists[0].name,
        album: track.album.name,
        uri: track.uri
      }));
    });
  },

  async savePlaylist(name, trackUris) {
    if (!name || !trackUris.length) return;
    const token = await this.getAccessToken();
    const headers = { Authorization: `Bearer ${token}` };

    const userRes = await fetch('https://api.spotify.com/v1/me', { headers });
    const userId = (await userRes.json()).id;

    const playlistRes = await fetch(`https://api.spotify.com/v1/users/${userId}/playlists`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name })
    });
    const playlistId = (await playlistRes.json()).id;

    return fetch(`https://api.spotify.com/v1/playlists/${playlistId}/tracks`, {
      method: "POST",
      headers,
      body: JSON.stringify({ uris: trackUris })
    });
  }
};

export default Spotify;

/* Old case for Implicit Flow method. Outdated as of April 2025.

const clientId = 'c5f4c6e4d986474081c716224f9930c6'; // Insert client ID here.
const redirectUri = 'https://jakemurph123.github.io/newspotify/'; // Have to add this to your accepted Spotify redirect URIs on the Spotify API.
let accessToken;

const Spotify = {
  getAccessToken() {
    if (accessToken) {
      return accessToken;
    }
    const accessTokenMatch = window.location.href.match(/access_token=([^&]*)/);
    const expiresInMatch = window.location.href.match(/expires_in=([^&]*)/);
    if (accessTokenMatch && expiresInMatch) {
      accessToken = accessTokenMatch[1];
      const expiresIn = Number(expiresInMatch[1]);
      window.setTimeout(() => accessToken = '', expiresIn * 1000);
      window.history.pushState('Access Token', null, '/'); // This clears the parameters, allowing us to grab a new access token when it expires.
      return accessToken;
    } else {
      const accessUrl = `https://accounts.spotify.com/authorize?client_id=${clientId}&response_type=token&scope=playlist-modify-public&redirect_uri=${redirectUri}`;
      window.location = accessUrl;
    }
  },
  search(term) {
    const accessToken = Spotify.getAccessToken();
    return fetch(`https://api.spotify.com/v1/search?type=track&q=${term}`, {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    }).then(response => {
      return response.json();
    }).then(jsonResponse => {
      if (!jsonResponse.tracks) {
        return [];
      }
      return jsonResponse.tracks.items.map(track => ({
        id: track.id,
        name: track.name,
        artist: track.artists[0].name,
        album: track.album.name,
        uri: track.uri
      }));
    });
  },
  savePlaylist(name, trackUris) {
    if (!name || !trackUris.length) {
      return;
    }
    const accessToken = Spotify.getAccessToken();
    const headers = { Authorization: `Bearer ${accessToken}` };
    let userId;
    return fetch('https://api.spotify.com/v1/me', {headers: headers}
    ).then(response => response.json()
    ).then(jsonResponse => {
      userId = jsonResponse.id;
      return fetch(`https://api.spotify.com/v1/users/${userId}/playlists`, {
        headers: headers,
        method: 'POST',
        body: JSON.stringify({name: name})
      }).then(response => response.json()
      ).then(jsonResponse => {
        const playlistId = jsonResponse.id;
        return fetch(`https://api.spotify.com/v1/users/${userId}/playlists/${playlistId}/tracks`, {
          headers: headers,
          method: 'POST',
          body: JSON.stringify({uris: trackUris})
        });
      });
    });
  }
};

export default Spotify;
*/