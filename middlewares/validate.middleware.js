export const validate = (schema) => (req, res, next) => {
  try {
    schema.parse(req.body);
    next();
  } catch (err) {
    return res.status(411).json({
      success: false,
      message: "Invalid or missing input",
      errors: err.errors.map(e => ({
        field: e.path.join("."),
        message: e.message
      }))
    });
  }
};
