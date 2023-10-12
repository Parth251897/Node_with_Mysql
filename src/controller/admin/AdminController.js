 const express = require("express");
 require("dotenv").config();
 const bcrypt = require("bcrypt");
 const jwt = require("jsonwebtoken");
 require("dotenv").config();
 const { StatusCodes } = require("http-status-codes");
const responsemessage = require("../../utils/ResponseMessage.json");
const {
  passwordencrypt, 
  validatePassword,
} = require("../../services/CommonService");
const { admingenerateJwt } = require("../../utils/jwt");
const connection = require("../../config/Db.config");



exports.AdminSingup = (req, res) => {
  let { adminName, email, phone, password } = req.body;
  try {
    const checkQuery = "SELECT * FROM admin WHERE email = ? OR phone = ?";
    connection.query(checkQuery, [email, phone], async (error, results) => {
      let existemail = results.find((admin) => admin.email === email);
      let existphone = results.find(
        (admin) => admin.phone === parseInt(phone, 10)
      );

      if (existemail || existphone) {
        const message = existemail
          ? responsemessage.EMAILEXITS
          : responsemessage.phoneEXITS;

        res.status(400).json({
          status: StatusCodes.BAD_REQUEST,
          message,
        });
      } else {
        if (!validatePassword(password)) {
          return res.status(400).json({
            status: StatusCodes.BAD_REQUEST,
            message: responsemessage.VALIDATEPASS,
          });
        } else {
          const hashPassword = await passwordencrypt(password);
          const insertQuery =
            "INSERT INTO admin (adminName, email, phone, password) VALUES (?, ?, ?, ?)";
          connection.query(
            insertQuery,
            [adminName, email, phone, hashPassword],
            (error, insertResults) => {
              if (error) {
                return res.status(400).json({
                  status: StatusCodes.BAD_REQUEST,
                  message: responsemessage.NOTCREATED,
                });
              } else {
                return res.status(201).json({
                  status: StatusCodes.CREATED,
                  message: responsemessage.CREATED,
                });
              }
            }
          );
        }
      }
    });
  } catch (error) {
    return res.status(500).json({
      status: StatusCodes.INTERNAL_SERVER_ERROR,
      message: responsemessage.INTERNAL_SERVER_ERROR,
    });
  }
};

exports.AdminSingIn = async (req, res) => {
  try {
    const { masterfield,adminName, email, phone, password } = req.body;

    const selectdata =
      "SELECT * FROM admin WHERE email = ? OR adminName = ? OR phone = ?";
    connection.query(
      selectdata,
      [masterfield, masterfield, masterfield],
      async (err, results) => {
        if (!results || results.length === 0) {
          return res.status(404).json({
            status: 404,
            error: true,
            message: responsemessage.NOTFOUND,
          });
        } else {
          const userLogin = results[0];

          if (userLogin.isactive) {
            return res.status(401).json({
              status: StatusCodes.UNAUTHORIZED,
              message: responsemessage.UNAUTHORIZED,
            });
          } else {
            const isvalid = await bcrypt.compare(password, userLogin.password);

            if (!isvalid) {
              return res.status(400).json({
                status: StatusCodes.BAD_REQUEST,
                error: true,
                message: responsemessage.NOTMATCH,
              });
            } else {
              const { error, token } = await admingenerateJwt(userLogin.id);
              if (error) {
                return res.status(400).json({
                  status: StatusCodes.BAD_REQUEST,
                  error: true,
                  message: responsemessage.TOKEN,
                });
              } else {
                return res.status(200).json({
                  status: StatusCodes.OK,
                  userLogin: userLogin.email,
                  phone: userLogin.phone,
                  success: true,
                  token: token,
                  message: responsemessage.SUCCESS,
                });
              }
            }
          }
        }
      }
    );
  } catch (error) {
    return res.status(500).json({
      status: StatusCodes.INTERNAL_SERVER_ERROR,
      message: responsemessage.INTERNAL_SERVER_ERROR,
    });
  }
};

exports.Updateadmin = async (req, res) => {
  try {
    let { email, phone } = req.body;
   
    let userId = req.AdminUser;

    const selectQuery = "SELECT * FROM admin WHERE id = ?";

    connection.query(selectQuery, [userId], async (error, results) => {
      if (error) {
        return res.status(400).json({
          status: StatusCodes.BAD_REQUEST,
          message: responsemessage.NOTFOUND,
        });
      } else {
        const existingUser = results[0];
        const checkQuery =
          "SELECT * FROM admin WHERE email = ? OR phone = ?";

        connection.query(
          checkQuery,
          [email, phone],
          async (error, results) => {
            let existemail = results.find(
              (admin) => admin.email === email
            );

            const existphone = results.find(
              (admin) => admin.phone === parseInt(phone, 10)
            );

            if (existemail || existphone) {
              const message = existemail
                ? responsemessage.EMAILEXITS
                : responsemessage.phoneEXITS;

              res.status(400).json({
                status: StatusCodes.BAD_REQUEST,
                message,
              });
            } else {
           
              const updatedatas = [];
              const updateValues = [];

              if (email) {
                updatedatas.push("email = ?");
                updateValues.push(email.toLowerCase());
              }
              if (phone) {
                updatedatas.push("phone = ?");
                updateValues.push(phone);
              }
             
              if (updatedatas.length === 0) {
                return res.status(404).json({
                  status: StatusCodes.NOT_FOUND,
                  message: responsemessage.NOTFOUND,
                });
              } else {
                const updateQuery = `UPDATE admin SET ${updatedatas.join(
                  ", "
                )} WHERE id = ?`;
                updateValues.push(userId);

                connection.query(updateQuery, updateValues, (error) => {
                  if (error) {
                    return res.status(400).json({
                      status: StatusCodes.BAD_REQUEST,
                      message: responsemessage.NOTUPDATE,
                    });
                  }

                  res.status(200).json({
                    status: StatusCodes.OK,
                    message: responsemessage.UPDATE,
                  });
                });
              }
            }
          }
        );
      }
    });
  } catch (error) {
    return res.status(500).json({
      status: StatusCodes.INTERNAL_SERVER_ERROR,
      message: responsemessage.INTERNAL_SERVER_ERROR,
    });
  }
};

exports.Adminchangepassword = async (req, res) => {
  try {

    const userId = req.AdminUser;
    const {oldPassword, newPassword, confirmPassword } = req.body;
  
    const selectQuery = "SELECT * FROM admin WHERE id = ?";

    connection.query(selectQuery, [userId], async (error, results) => {
      if (results.length === 0) {
        return res.status(404).json({
          status: StatusCodes.NOT_FOUND,
          message: responsemessage.NOTFOUND,
        });
      } else {
        const user = results[0];
        console.log(user);

        if (!validatePassword(newPassword)) {
          return res.status(400).json({
            status: StatusCodes.BAD_REQUEST,
            message: responsemessage.VALIDATEPASS,
          });
        } else {
          const isMatch = await bcrypt.compare(oldPassword, user.password);

          if (!isMatch) {
            return res.status(400).json({
              status: StatusCodes.BAD_REQUEST,
              message: responsemessage.OLDPASSWORD,
            });
          } else {
            const isSamePassword = await bcrypt.compare(
              newPassword,
              user.password
            );
            if (isSamePassword) {
              return res.status(400).json({
                status: StatusCodes.BAD_REQUEST,
                message: responsemessage.OLDPASSWORDMATCH,
              });
            } else if (newPassword !== confirmPassword) {
              return res.status(400).json({
                status: StatusCodes.BAD_REQUEST,
                message: responsemessage.PASSWORDMATCH,
              });
            } else {
              const hashedPassword = await passwordencrypt(newPassword);
              const updateQuery =
                "UPDATE admin SET password = ? WHERE id = ?";
              connection.query(
                updateQuery,
                [hashedPassword, userId],
                (updateError) => {
                  if (updateError) {
                    console.log(updateError);
                    return res.status(400).json({
                      status: StatusCodes.BAD_REQUEST,
                      message: responsemessage.PASSNOTCHANGE,
                    });
                  } else {
                    return res.status(200).json({
                      status: StatusCodes.OK,
                      message: responsemessage.PASSWORDCHANGE,
                    });
                  }
                }
              );
            }
          }
        }
      }
    });
  } catch (error) {
    return res.status(500).json({
      status: StatusCodes.INTERNAL_SERVER_ERROR,
      message: responsemessage.INTERNAL_SERVER_ERROR,
    });
  }
};

exports.Adminlogout = (req, res) => {
  const userId = req.AdminUser;

  connection.query(
    "SELECT * FROM empdata WHERE id = ?",
    [userId],
    (error, results) => {
      if (error) {
        // console.log(error);
        return res.status(400).json({
          status: StatusCodes.BAD_REQUEST,
          message: responsemessage.LOGOUTERROR,
        });
      }

      return res.status(200).json({
        status: StatusCodes.OK,
        message: responsemessage.LOGOUT,
      });
    }
  );
};
