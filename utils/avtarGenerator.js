/**
 * Function: fetchAvatar
 * Purpose: Generate an avatar URL based on the user's gender.
 * 
 * Description:
 *  - The function determines the URL of a randomly selected avatar image.
 *  - Male users receive one avatar URL, and female users receive another.
 * 
 * @param {string} gender - The gender of the user ("male" or "female").
 * @returns {Promise<string>} - The URL of the avatar image.
 */
const fetchAvatar = async (gender) => {
  /**
   * Determine the avatar URL based on gender:
   *  - If the gender is "male", use the URL for the male avatar.
   *  - If the gender is "female", use the URL for the female avatar.
   * 
   * Note: These URLs point to LEGO-style avatars from randomuser.me for simplicity.
   */
  const apiUrl =
    gender === "male"
      ? "https://randomuser.me/api/portraits/lego/0.jpg" // Male avatar URL
      : "https://randomuser.me/api/portraits/lego/1.jpg"; // Female avatar URL

  // Return the selected avatar URL
  return apiUrl;
};

// Export the function for use in other parts of the application
module.exports = fetchAvatar;
